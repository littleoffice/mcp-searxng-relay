package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A caller may embed credentials in a URL — basic auth against an internal
// service reached through FETCH_ALLOWED_HOSTS is the obvious case. The fetch
// needs them; nothing that outlives the fetch does. These tests pin that the
// credential never reaches a log line, the session ledger, or the model.

func TestRedactURLCredentials(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no credentials", "https://example.com/a?b=c", "https://example.com/a?b=c"},
		{"user and password", "https://alice:s3cret@example.com/a", "https://example.com/a"},
		{"user only", "https://alice@example.com/a", "https://example.com/a"},
		{"port preserved", "https://alice:s3cret@example.com:8443/a", "https://example.com:8443/a"},
		{"query preserved", "https://alice:s3cret@example.com/a?x=1&y=2", "https://example.com/a?x=1&y=2"},
		// An "@" outside the authority is ordinary data and must survive.
		{"at sign in path", "https://example.com/users/@alice", "https://example.com/users/@alice"},
		{"at sign in query", "https://example.com/s?q=a@b.com", "https://example.com/s?q=a@b.com"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactURLCredentials(tc.in); got != tc.want {
				t.Errorf("redactURLCredentials(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// url.Parse is permissive, so the fallback path is hard to reach by accident —
// but it is the branch that runs exactly when parsing gave up, which is the
// worst moment to hand back the original string.
func TestRedactURLCredentials_UnparseableStillStrips(t *testing.T) {
	// A control character makes url.Parse fail outright.
	raw := "https://alice:s3cret@example.com/\x7f/bad"
	got := redactURLCredentials(raw)

	if strings.Contains(got, "s3cret") {
		t.Errorf("redactURLCredentials(%q) = %q, still contains the password", raw, got)
	}
	if !strings.Contains(got, "example.com") {
		t.Errorf("redactURLCredentials(%q) = %q, lost the host", raw, got)
	}
}

// End to end: the exact leak this change exists to close. The credential must
// not appear in the audit log, nor in the fenced payload handed to the model.
func TestToolReadURL_CredentialNeverEscapesTheFetch(t *testing.T) {
	s := NewServer(Config{
		CacheMaxEntries:   8,
		CacheTTL:          time.Minute,
		MaxExtractedChars: 1000,
		HistoryEntries:    10,
	})
	const (
		target   = "https://svc-account:hunter2@wiki.corp.internal/page"
		password = "hunter2"
	)

	// Pre-seed so the test needs no origin and no SSRF exemption.
	s.cache.Add(target, cacheEntry{
		content:   "internal page body",
		expiresAt: time.Now().Add(time.Minute),
		finalURL:  target,
		fetchedAt: time.Now(),
	})

	var fenced string
	recs := captureRecords(t, func() {
		res, _, err := s.toolReadURL(context.Background(), nil, fetchInput{URL: target})
		if err != nil {
			t.Fatalf("toolReadURL: %v", err)
		}
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			fenced = tc.Text
		}
	})

	// 1. Not in any log record, at any level.
	for _, rec := range recs {
		for k, v := range rec {
			if sv, ok := v.(string); ok && strings.Contains(sv, password) {
				t.Errorf("password leaked into log field %q of record %q: %s", k, rec["msg"], sv)
			}
		}
	}

	// 2. Not in the fenced response, which becomes model context. The fence
	//    `source` attribute is the specific carrier.
	if strings.Contains(fenced, password) {
		t.Error("password leaked into the fenced response sent to the model")
	}

	// The redacted form must still be present and useful — stripping the
	// credential is not licence to lose the URL.
	rec := findRecord(t, recs, "fetch completed")
	if got := rec["url"]; got != "https://wiki.corp.internal/page" {
		t.Errorf("log url = %v, want the redacted URL", got)
	}
	if got := rec["domain"]; got != "wiki.corp.internal" {
		t.Errorf("log domain = %v, want %q", got, "wiki.corp.internal")
	}
	if !strings.Contains(fenced, "wiki.corp.internal") {
		t.Error("fence lost the source host entirely; it should carry the redacted URL")
	}
}

// The ledger is read back into model context by searxng_session_sources, so a
// credential surviving there is the same leak one call later.
func TestSessionLedger_StoresRedactedURL(t *testing.T) {
	s := NewServer(Config{
		CacheMaxEntries:   8,
		CacheTTL:          time.Minute,
		MaxExtractedChars: 1000,
		HistoryEntries:    10,
	})
	const target = "https://svc-account:hunter2@wiki.corp.internal/page"

	s.cache.Add(target, cacheEntry{
		content:   "internal page body",
		expiresAt: time.Now().Add(time.Minute),
		finalURL:  target,
		fetchedAt: time.Now(),
	})

	ctx := context.Background()
	if _, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: target}); err != nil {
		t.Fatalf("toolReadURL: %v", err)
	}

	res, _, err := s.toolSessionSources(ctx, nil, sessionSourcesInput{})
	if err != nil {
		t.Fatalf("toolSessionSources: %v", err)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("expected text content from searxng_session_sources")
	}
	if strings.Contains(tc.Text, "hunter2") {
		t.Error("password leaked through the session ledger into model context")
	}
	if !strings.Contains(tc.Text, "wiki.corp.internal") {
		t.Error("ledger lost the URL entirely; it should carry the redacted form")
	}
}
