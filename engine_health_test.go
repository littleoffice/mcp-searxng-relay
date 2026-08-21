package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
