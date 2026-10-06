package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

// The completion log lines are the only place domain and duration appear
// together: putting a domain label on a latency histogram would mean 512
// domains times a dozen buckets of Prometheus series, so "which domains are
// slow" is deliberately a log query instead.  That only works if the fields
// are actually on the line, which is what these tests pin.

// captureRecords runs fn with a JSON handler installed and returns every
// record written, rather than the single one captureLog expects — a tool call
// emits several lines and the interesting one is rarely the only one.
func captureRecords(t *testing.T, fn func()) []map[string]any {
	t.Helper()

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	defer slog.SetDefault(prev)

	fn()

	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("decoding log record: %v (raw: %q)", err, line)
		}
		out = append(out, rec)
	}
	return out
}

// findRecord returns the first record whose "msg" matches, failing the test
// if none does — an absent line is a more useful failure than a nil map.
func findRecord(t *testing.T, recs []map[string]any, msg string) map[string]any {
	t.Helper()
	for _, r := range recs {
		if r["msg"] == msg {
			return r
		}
	}
	var seen []any
	for _, r := range recs {
		seen = append(seen, r["msg"])
	}
	t.Fatalf("no log record with msg=%q; saw %v", msg, seen)
	return nil
}

func TestFetchCompleted_CarriesDomainAndDuration(t *testing.T) {
	s := NewServer(Config{CacheMaxEntries: 8, CacheTTL: time.Minute, MaxExtractedChars: 1000})
	const target = "https://example.com/some/article"

	// Serve from cache so the test needs no origin and no SSRF exemption.
	s.cache.Add(target, cacheEntry{
		content:   "hello",
		expiresAt: time.Now().Add(time.Minute),
		finalURL:  target,
		fetchedAt: time.Now(),
	})

	recs := captureRecords(t, func() {
		if _, _, err := s.toolReadURL(context.Background(), nil, fetchInput{URL: target}); err != nil {
			t.Fatalf("toolReadURL: %v", err)
		}
	})
	rec := findRecord(t, recs, "fetch completed")

	if got := rec["domain"]; got != "example.com" {
		t.Errorf("domain = %v, want %q", got, "example.com")
	}
	if got, ok := rec["duration_ms"].(float64); !ok || got < 0 {
		t.Errorf("duration_ms = %v, want a non-negative number", rec["duration_ms"])
	}
	if got := rec["from_cache"]; got != true {
		t.Errorf("from_cache = %v, want true", got)
	}
	if got := rec["outcome"]; got != "ok" {
		t.Errorf("outcome = %v, want %q", got, "ok")
	}
	// Attribution must survive alongside the new fields, since the whole
	// point is joining domain and timing to a caller.
	for _, k := range []string{"identity", "session_id"} {
		if _, ok := rec[k]; !ok {
			t.Errorf("record is missing the %q attribution key", k)
		}
	}
}

// A failure has to be as queryable as a success, otherwise the slow-domain
// query silently excludes the domains that are timing out.
func TestFetchFailed_CarriesDomainAndDuration(t *testing.T) {
	s := NewServer(Config{CacheMaxEntries: 8, CacheTTL: time.Minute})

	recs := captureRecords(t, func() {
		// Rejected scheme: fails without touching the network.
		_, _, _ = s.toolReadURL(context.Background(), nil, fetchInput{URL: "ftp://blocked.example.org/x"})
	})
	rec := findRecord(t, recs, "fetch failed")

	if got := rec["domain"]; got != "blocked.example.org" {
		t.Errorf("domain = %v, want %q", got, "blocked.example.org")
	}
	if _, ok := rec["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms = %v, want a number", rec["duration_ms"])
	}
	if got := rec["outcome"]; got != "error" {
		t.Errorf("outcome = %v, want %q", got, "error")
	}
}

func TestSearchAndSourcesLines_CarryDuration(t *testing.T) {
	s := NewServer(Config{CacheMaxEntries: 8, HistoryEntries: 10})

	recs := captureRecords(t, func() {
		if _, _, err := s.toolSessionSources(context.Background(), nil, sessionSourcesInput{}); err != nil {
			t.Fatalf("toolSessionSources: %v", err)
		}
	})
	rec := findRecord(t, recs, "session sources listed")

	if _, ok := rec["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms = %v, want a number", rec["duration_ms"])
	}
	if got := rec["outcome"]; got != "ok" {
		t.Errorf("outcome = %v, want %q", got, "ok")
	}
}
