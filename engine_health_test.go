package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The wire shape comes from SearXNG's searx/webutils.py:get_json_response,
// which serialises get_translated_errors() — a list of (engine, message)
// tuples, which JSON-encodes as a list of two-element arrays.
const searxUnresponsiveWire = `[["google","Suspended: Access denied"],["bing","timeout"]]`

func TestParseUnresponsiveEngines_UpstreamShape(t *testing.T) {
	got := parseUnresponsiveEngines(json.RawMessage(searxUnresponsiveWire))
	if len(got) != 2 {
		t.Fatalf("expected 2 failures, got %d (%+v)", len(got), got)
	}
	if got[0].Engine != "google" || got[0].Reason != "Suspended: Access denied" {
		t.Errorf("first entry = %+v", got[0])
	}
	if got[1].Engine != "bing" || got[1].Reason != "timeout" {
		t.Errorf("second entry = %+v", got[1])
	}
}

// Every unrecognised input degrades to "no engine information" rather than an
// error. The field is diagnostic metadata; it must never be able to fail a
// search that SearXNG answered successfully.
func TestParseUnresponsiveEngines_ToleratesJunk(t *testing.T) {
	for _, raw := range []string{
		``,                             // field absent
		`null`,                         // explicit null
		`[]`,                           // no failures — the healthy case
		`[[]]`,                         // empty entry
		`[["google"]]`,                 // one element, shape we don't know
		`[["","reason"]]`,              // no engine name
		`{"google":"down"}`,            // an object, i.e. upstream changed shape
		`"everything is on fire"`,      // a bare string
		`[[{"engine":"g"},{"e":"x"}]]`, // nested objects
	} {
		if got := parseUnresponsiveEngines(json.RawMessage(raw)); got != nil {
			t.Errorf("parseUnresponsiveEngines(%s) = %+v, want nil", raw, got)
		}
	}
}

// A shape change upstream must not break search. This is the property the
// json.RawMessage indirection exists for: if unresponsive_engines were typed
// as [][]string directly, an object here would fail the whole decode and take
// the results down with it.
func TestSearchSurvivesUnresponsiveEnginesShapeChange(t *testing.T) {
	body := `{"results":[{"title":"T","url":"https://example.com","content":"C"}],
	          "unresponsive_engines":{"google":"changed shape upstream"}}`
	var resp searxNGResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("a shape change in unresponsive_engines must not fail the decode: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("results should still decode, got %d", len(resp.Results))
	}
	if parseUnresponsiveEngines(resp.UnresponsiveEngines) != nil {
		t.Error("unrecognised shape should yield no engine information")
	}
}

// End-to-end through the real search path: a SearXNG reporting dead engines
// must still return its results, and must emit the degraded warning naming
// them. This is the case that previously produced silence.
func TestSearch_DegradedEmitsWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"title":"T","url":"https://example.com","content":"C"}],
		                        "unresponsive_engines":` + searxUnresponsiveWire + `}`))
	}))
	defer srv.Close()

	s := &Server{config: Config{SearxngURL: srv.URL}, client: srv.Client()}

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	results, err := s.search(context.Background(), "q", 1, "", "all", "", 0, "")
	slog.SetDefault(old)

	if err != nil {
		t.Fatalf("a degraded search is still a successful search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results should be returned despite dead engines, got %d", len(results))
	}
	log := buf.String()
	if !strings.Contains(log, "level=WARN") {
		t.Errorf("expected a WARN line, got: %s", log)
	}
	for _, want := range []string{"degraded", "google", "bing", "unresponsive_count=2"} {
		if !strings.Contains(log, want) {
			t.Errorf("log should mention %q, got: %s", want, log)
		}
	}
}

// The healthy case stays quiet. A warning on every search would train
// operators to ignore the one that matters.
func TestSearch_HealthyIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"title":"T","url":"https://example.com","content":"C"}],
		                        "unresponsive_engines":[]}`))
	}))
	defer srv.Close()

	s := &Server{config: Config{SearxngURL: srv.URL}, client: srv.Client()}

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	_, err := s.search(context.Background(), "q", 1, "", "all", "", 0, "")
	slog.SetDefault(old)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "degraded") {
		t.Errorf("a healthy search must not warn, got: %s", buf.String())
	}
}

// ── Metrics ──────────────────────────────────────────────────────────────────

// A degraded search increments the degraded counter once and each failing
// engine's counter once. The ratio of the former to mcp_searches_total is the
// number that decides whether backend flakiness is worth acting on.
func TestMetrics_DegradedSearchCounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"title":"T","url":"https://e.example","content":"C"}],
		                        "unresponsive_engines":` + searxUnresponsiveWire + `}`))
	}))
	defer srv.Close()
	s := &Server{config: Config{SearxngURL: srv.URL}, client: srv.Client()}

	for i := 0; i < 3; i++ {
		if _, err := s.search(context.Background(), "q", 1, "", "all", "", 0, ""); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if got := s.metrics.SearchesDegraded.Load(); got != 3 {
		t.Errorf("SearchesDegraded = %d, want 3", got)
	}
	// A degraded search is still a successful one — conflating the two would
	// make "returned fewer results than it should have" indistinguishable
	// from "returned nothing".
	if got := s.metrics.SearchErrors.Load(); got != 0 {
		t.Errorf("SearchErrors = %d, want 0: a degraded search is not a failed search", got)
	}

	body := serveMetricsBody(t, s)
	for _, want := range []string{
		`mcp_searches_degraded_total 3`,
		`mcp_searxng_engine_errors_total{engine="bing"} 3`,
		`mcp_searxng_engine_errors_total{engine="google"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
}

// A healthy search touches neither counter, and the series are still exposed
// at zero so a dashboard does not show gaps before the first failure.
func TestMetrics_HealthySearchNotCounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"title":"T","url":"https://e.example","content":"C"}],
		                        "unresponsive_engines":[]}`))
	}))
	defer srv.Close()
	s := &Server{config: Config{SearxngURL: srv.URL}, client: srv.Client()}

	if _, err := s.search(context.Background(), "q", 1, "", "all", "", 0, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := s.metrics.SearchesDegraded.Load(); got != 0 {
		t.Errorf("SearchesDegraded = %d, want 0", got)
	}
	if body := serveMetricsBody(t, s); !strings.Contains(body, "mcp_searches_degraded_total 0") {
		t.Error("the degraded series should be exposed at zero, not omitted")
	}
}

// Engine-name cardinality is bounded even though the names come from upstream
// rather than from a caller: a misconfigured or compromised SearXNG must not
// be able to grow the map without limit.
func TestMetrics_EngineCardinalityBounded(t *testing.T) {
	var m Metrics
	for i := 0; i < maxTrackedEngines+50; i++ {
		m.recordEngineFailure(fmt.Sprintf("engine-%04d", i))
	}
	m.enginesMu.RLock()
	tracked := len(m.engineErrors)
	m.enginesMu.RUnlock()

	if tracked > maxTrackedEngines {
		t.Errorf("tracked %d engines, cap is %d", tracked, maxTrackedEngines)
	}
	if got := m.EngineErrorOverflow.Load(); got != 50 {
		t.Errorf("overflow = %d, want 50", got)
	}
}

// An empty engine name is bucketed rather than creating an unlabelled series.
func TestMetrics_EmptyEngineName(t *testing.T) {
	var m Metrics
	m.recordEngineFailure("")
	m.enginesMu.RLock()
	_, ok := m.engineErrors["unknown"]
	m.enginesMu.RUnlock()
	if !ok {
		t.Error("an empty engine name should be recorded as \"unknown\"")
	}
}

// Concurrent recording of the same and different engines must not race and
// must not lose counts — the -race detector plus an exact total.
func TestMetrics_EngineFailuresConcurrent(t *testing.T) {
	var m Metrics
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				m.recordEngineFailure(fmt.Sprintf("engine-%d", i%5))
			}
		}(i)
	}
	wg.Wait()

	var total int64
	m.enginesMu.RLock()
	for _, c := range m.engineErrors {
		total += c.Load()
	}
	m.enginesMu.RUnlock()
	if total != 1000 {
		t.Errorf("total recorded failures = %d, want 1000", total)
	}
}

// serveMetricsBody renders /metrics for a server, for assertions on the
// exposition format rather than on the counters behind it.
func serveMetricsBody(t *testing.T, s *Server) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.ServeMetrics(w, httptest.NewRequest("GET", "/metrics", nil))
	return w.Body.String()
}
