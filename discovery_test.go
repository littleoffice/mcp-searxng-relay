package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// configJSON is a minimal SearXNG /config body with a mix of categories,
// an explicitly disabled engine, and one that would be a private backend.
const configJSON = `{
  "engines": [
    {"name": "google",    "categories": ["general", "web"], "enabled": true},
    {"name": "gitea",     "categories": ["it"],             "enabled": true},
    {"name": "wikipedia", "categories": ["general"],        "enabled": true},
    {"name": "arxiv",     "categories": ["science"],        "enabled": true},
    {"name": "off_engine","categories": ["general"],        "enabled": false},
    {"name": "secret_forge","categories": ["it"],           "enabled": true}
  ]
}`

// configServer returns an httptest server serving body at /config and 404
// elsewhere, plus the base URL to use as SEARXNG_URL.
func configServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func discover(t *testing.T, cfg Config) []engineDescriptor {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	roster, err := discoverEngines(ctx, cfg, &http.Client{Timeout: 5 * time.Second}, nil)
	if err != nil {
		t.Fatalf("discoverEngines returned error: %v", err)
	}
	return roster
}

func TestDiscoverEngines_AllEnabled(t *testing.T) {
	srv := configServer(t, http.StatusOK, configJSON)
	defer srv.Close()

	roster := discover(t, Config{SearxngURL: srv.URL})

	// The disabled engine is dropped; everything else is present, in /config order.
	if got, want := strings.Join(rosterNames(roster), ","), "google,gitea,wikipedia,arxiv,secret_forge"; got != want {
		t.Fatalf("names = %q, want %q", got, want)
	}
	// Purpose is derived from categories.
	if roster[0].Purpose != "general, web" {
		t.Errorf("google purpose = %q, want %q", roster[0].Purpose, "general, web")
	}
}

func TestDiscoverEngines_CategoryAllowlist(t *testing.T) {
	srv := configServer(t, http.StatusOK, configJSON)
	defer srv.Close()

	roster := discover(t, Config{
		SearxngURL:         srv.URL,
		DiscoverCategories: []string{"it"},
	})

	// Only the two "it" engines survive the allowlist.
	if got, want := strings.Join(rosterNames(roster), ","), "gitea,secret_forge"; got != want {
		t.Fatalf("names = %q, want %q", got, want)
	}
}

func TestDiscoverEngines_ExcludeList(t *testing.T) {
	srv := configServer(t, http.StatusOK, configJSON)
	defer srv.Close()

	roster := discover(t, Config{
		SearxngURL:     srv.URL,
		ExcludeEngines: []string{"secret_forge"},
	})

	for _, e := range roster {
		if e.Name == "secret_forge" {
			t.Fatalf("excluded engine was advertised: %+v", roster)
		}
	}
}

func TestDiscoverEngines_Cap(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"engines": [`)
	for i := 0; i < maxDiscoveredEngines+10; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"name": "e%d", "categories": ["general"], "enabled": true}`, i)
	}
	sb.WriteString("]}")

	srv := configServer(t, http.StatusOK, sb.String())
	defer srv.Close()

	roster := discover(t, Config{SearxngURL: srv.URL})
	if len(roster) != maxDiscoveredEngines {
		t.Fatalf("roster length = %d, want cap %d", len(roster), maxDiscoveredEngines)
	}
}

func TestDiscoverEngines_SoftFailOn403(t *testing.T) {
	srv := configServer(t, http.StatusForbidden, "forbidden")
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := discoverEngines(ctx, Config{SearxngURL: srv.URL}, &http.Client{Timeout: 5 * time.Second}, nil); err == nil {
		t.Fatal("expected an error for a 403 /config (caller falls back to the manual roster), got nil")
	}
}

func TestDiscoverEngines_SoftFailOnUnreachable(t *testing.T) {
	// A port nothing listens on: the request fails, and the error is the
	// caller's cue to fall back — exactly the hardened-instance path.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := discoverEngines(ctx, Config{SearxngURL: "http://127.0.0.1:0"}, &http.Client{Timeout: 2 * time.Second}, nil); err == nil {
		t.Fatal("expected an error for an unreachable /config, got nil")
	}
}

func TestMergeRosters_Precedence(t *testing.T) {
	// discovered: gitea + google with category-derived purposes.
	discovered := []engineDescriptor{
		{Name: "gitea", Purpose: "it"},
		{Name: "google", Purpose: "general"},
	}
	// manual layers on top: overrides gitea's purpose, adds arxiv, and mentions
	// google name-only (which must NOT wipe the discovered purpose).
	manual := []engineDescriptor{
		{Name: "gitea", Purpose: "our self-hosted forge"},
		{Name: "arxiv", Purpose: "preprints"},
		{Name: "google"},
	}

	merged := mergeRosters(discovered, manual)

	// Display order follows first appearance (discovered first), manual-only appended.
	if got, want := strings.Join(rosterNames(merged), ","), "gitea,google,arxiv"; got != want {
		t.Fatalf("order = %q, want %q", got, want)
	}
	byName := map[string]string{}
	for _, e := range merged {
		byName[e.Name] = e.Purpose
	}
	if byName["gitea"] != "our self-hosted forge" {
		t.Errorf("gitea purpose = %q, want manual override to win", byName["gitea"])
	}
	if byName["google"] != "general" {
		t.Errorf("google purpose = %q, want discovered purpose preserved (name-only manual mention must not wipe it)", byName["google"])
	}
}
