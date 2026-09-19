package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mcp_fetch_duration_seconds is split by cache outcome so that a cache hit,
// which returns in microseconds, cannot drag the quantiles of a real network
// fetch toward zero.  These tests pin the two halves of that: the exposition
// is a valid single metric family, and readURL files each call under the
// right outcome.

func TestFetchDuration_ExposedPerCacheOutcome(t *testing.T) {
	s := NewServer(Config{CacheMaxEntries: 1})
	s.metrics.FetchDuration[cacheOutcomeHit].Observe(2 * time.Millisecond)
	s.metrics.FetchDuration[cacheOutcomeMiss].Observe(1200 * time.Millisecond)

	rec := httptest.NewRecorder()
	s.ServeMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		// Declared once for the whole family; Prometheus rejects a second
		// HELP/TYPE for the same metric name.
		"# TYPE mcp_fetch_duration_seconds histogram\n",
		`mcp_fetch_duration_seconds_bucket{cache="hit",le="0.05"} 1` + "\n",
		`mcp_fetch_duration_seconds_bucket{cache="hit",le="+Inf"} 1` + "\n",
		`mcp_fetch_duration_seconds_count{cache="hit"} 1` + "\n",
		// 1.2s falls in the 2.5s bucket, so the sub-second buckets stay 0.
		`mcp_fetch_duration_seconds_bucket{cache="miss",le="1"} 0` + "\n",
		`mcp_fetch_duration_seconds_bucket{cache="miss",le="2.5"} 1` + "\n",
		`mcp_fetch_duration_seconds_count{cache="miss"} 1` + "\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}

	if n := strings.Count(body, "# TYPE mcp_fetch_duration_seconds histogram"); n != 1 {
		t.Errorf("TYPE declared %d times for mcp_fetch_duration_seconds, want exactly 1", n)
	}
	if n := strings.Count(body, "# HELP mcp_fetch_duration_seconds"); n != 1 {
		t.Errorf("HELP declared %d times for mcp_fetch_duration_seconds, want exactly 1", n)
	}
	// The unlabelled form would silently break every existing query and is
	// what a half-finished split leaves behind.
	if strings.Contains(body, "mcp_fetch_duration_seconds_count ") {
		t.Error("found an unlabelled mcp_fetch_duration_seconds_count series")
	}
}

// +Inf must equal _count for every label set, the invariant the cumulative
// sum in writeSeries exists to preserve.
func TestFetchDuration_InfBucketEqualsCount(t *testing.T) {
	s := NewServer(Config{CacheMaxEntries: 1})
	for _, d := range []time.Duration{time.Millisecond, 400 * time.Millisecond, 90 * time.Second} {
		s.metrics.FetchDuration[cacheOutcomeMiss].Observe(d)
	}

	rec := httptest.NewRecorder()
	s.ServeMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	// 90s exceeds the last bucket, so it only shows up in +Inf — which is
	// precisely the case a non-cumulative overflow bug would drop.
	for _, want := range []string{
		`mcp_fetch_duration_seconds_bucket{cache="miss",le="30"} 2` + "\n",
		`mcp_fetch_duration_seconds_bucket{cache="miss",le="+Inf"} 3` + "\n",
		`mcp_fetch_duration_seconds_count{cache="miss"} 3` + "\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

// A served-from-cache read must be filed under cache="hit", and anything that
// performs real work under cache="miss".  Getting this backwards restores
// exactly the dilution the split removes, while still looking plausible on a
// dashboard — so it is worth pinning directly.
func TestReadURL_FilesDurationUnderCacheOutcome(t *testing.T) {
	s := NewServer(Config{CacheMaxEntries: 8, CacheTTL: time.Minute})
	const cached = "https://example.com/already-fetched"

	s.cache.Add(cached, cacheEntry{
		content:   "hello",
		expiresAt: time.Now().Add(time.Minute),
		finalURL:  cached,
		fetchedAt: time.Now(),
	})

	// Warm entry, no force refresh: served from cache.
	if _, err := s.readURL(t.Context(), cached, false); err != nil {
		t.Fatalf("cached readURL: %v", err)
	}
	if got := s.metrics.FetchDuration[cacheOutcomeHit].count.Load(); got != 1 {
		t.Errorf("hit count = %d, want 1", got)
	}
	if got := s.metrics.FetchDuration[cacheOutcomeMiss].count.Load(); got != 0 {
		t.Errorf("miss count = %d, want 0 — a cache hit must not land in the miss series", got)
	}

	// force_refresh drops the entry and refetches, so it is a miss no matter
	// how warm the cache was.  The fetch itself fails in this test (no
	// origin), which does not matter: the observation is deferred and fires
	// on every exit, which is the behaviour under test.
	_, _ = s.readURL(t.Context(), cached, true)
	if got := s.metrics.FetchDuration[cacheOutcomeMiss].count.Load(); got != 1 {
		t.Errorf("after force refresh, miss count = %d, want 1", got)
	}
	if got := s.metrics.FetchDuration[cacheOutcomeHit].count.Load(); got != 1 {
		t.Errorf("after force refresh, hit count = %d, want 1 (unchanged)", got)
	}

	// A URL that never reaches the cache branch at all still counts as a
	// miss rather than vanishing from the histogram.
	_, _ = s.readURL(t.Context(), "ftp://example.com/nope", false)
	if got := s.metrics.FetchDuration[cacheOutcomeMiss].count.Load(); got != 2 {
		t.Errorf("after a rejected scheme, miss count = %d, want 2", got)
	}
}
