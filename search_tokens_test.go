package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// These tests pin the SEARXNG_TOKENS contract: the configured private-engine
// tokens are sent on every search as the `tokens` parameter, and nothing is
// sent when none are configured.
//
// The negative case is the one that matters. On a shared SearXNG instance the
// separation between two relays is exactly "relay B never presents relay A's
// token", enforced upstream by SearXNG's validate_token. A regression that
// dropped the parameter would not fail loudly — searches would keep working,
// just without the private engines — so the assertion has to live here rather
// than being noticed in production.

// searchTestServer returns a Server pointed at a stub upstream, plus a pointer
// to the query values the stub last received.
func searchTestServer(t *testing.T, cfg Config) (*Server, *url.Values) {
	t.Helper()

	var lastQuery url.Values
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	t.Cleanup(upstream.Close)

	cfg.SearxngURL = upstream.URL
	if cfg.CacheMaxEntries == 0 {
		cfg.CacheMaxEntries = 1
	}
	return NewServer(cfg), &lastQuery
}

func TestSearch_SendsConfiguredTokens(t *testing.T) {
	s, got := searchTestServer(t, Config{
		SearxngTokens: []string{"token-a", "token-b"},
	})

	if _, err := s.search(context.Background(), "q", 1, "", "all", "", 0, "teama-confluence"); err != nil {
		t.Fatalf("search returned error: %v", err)
	}

	if want := "token-a,token-b"; (*got).Get("tokens") != want {
		t.Errorf("tokens parameter = %q, want %q", (*got).Get("tokens"), want)
	}
	if want := "teama-confluence"; (*got).Get("engines") != want {
		t.Errorf("engines parameter = %q, want %q", (*got).Get("engines"), want)
	}
}

func TestSearch_OmitsTokensWhenUnconfigured(t *testing.T) {
	s, got := searchTestServer(t, Config{})

	if _, err := s.search(context.Background(), "q", 1, "", "all", "", 0, ""); err != nil {
		t.Fatalf("search returned error: %v", err)
	}

	if _, present := (*got)["tokens"]; present {
		t.Errorf("tokens parameter must be absent when SEARXNG_TOKENS is unset, got %q", (*got).Get("tokens"))
	}
}

// A relay configured for one tenant must not present another tenant's token
// merely because the agent named that tenant's engine. The engine name is
// model-controlled; the token is not.
func TestSearch_TokensIndependentOfRequestedEngines(t *testing.T) {
	s, got := searchTestServer(t, Config{
		SearxngTokens: []string{"token-a"},
	})

	if _, err := s.search(context.Background(), "q", 1, "", "all", "", 0, "teamb-confluence"); err != nil {
		t.Fatalf("search returned error: %v", err)
	}

	if want := "token-a"; (*got).Get("tokens") != want {
		t.Errorf("tokens parameter = %q, want %q — tokens come from config, never from the request",
			(*got).Get("tokens"), want)
	}
}

// redactedUpstreamURL must never let a configured SEARXNG_TOKENS value reach a
// log line. The non-200 path logs the upstream URL, and the raw URL carries the
// tokens in its query string; a regression here would leak operator credentials
// into the general log stream at WARN.
func TestRedactedUpstreamURL_StripsTokens(t *testing.T) {
	u, err := url.Parse("http://searxng.invalid/search?q=hello&tokens=secret-a,secret-b&format=json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got := redactedUpstreamURL(u)

	if strings.Contains(got, "secret-a") || strings.Contains(got, "secret-b") {
		t.Fatalf("redacted URL still contains token material: %q", got)
	}
	if !strings.Contains(got, "tokens=%5Bredacted%5D") {
		t.Errorf("expected tokens to be replaced with a redaction marker, got %q", got)
	}
	// Non-secret diagnostic value must survive so the log line is still useful.
	if !strings.Contains(got, "q=hello") || !strings.Contains(got, "format=json") {
		t.Errorf("redaction dropped non-secret query parameters: %q", got)
	}
	// The original URL must not be mutated as a side effect of logging.
	if u.Query().Get("tokens") != "secret-a,secret-b" {
		t.Errorf("original URL was mutated by redaction: tokens = %q", u.Query().Get("tokens"))
	}
}

func TestRedactedUpstreamURL_NoTokensUnchanged(t *testing.T) {
	u, err := url.Parse("http://searxng.invalid/search?q=hello&format=json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := redactedUpstreamURL(u), u.String(); got != want {
		t.Errorf("redactedUpstreamURL with no tokens = %q, want unchanged %q", got, want)
	}
}

func TestConfigFromEnv_SearxngTokensCSV(t *testing.T) {
	t.Setenv("SEARXNG_URL", "http://searxng.invalid")
	t.Setenv("SEARXNG_TOKENS", " token-a , ,token-b ")

	cfg := configFromEnv()

	if len(cfg.SearxngTokens) != 2 {
		t.Fatalf("expected 2 tokens after CSV parsing, got %d: %q", len(cfg.SearxngTokens), cfg.SearxngTokens)
	}
	if cfg.SearxngTokens[0] != "token-a" || cfg.SearxngTokens[1] != "token-b" {
		t.Errorf("tokens not trimmed as expected: %q", cfg.SearxngTokens)
	}
}
