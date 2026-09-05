package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These cover the three guardrail counters added alongside the tool-usage
// metrics: mcp_ssrf_blocked_total, mcp_auth_failures_total and
// mcp_search_degraded_total. Each meters an event the relay already logged but
// never counted, so the dashboard can show the security boundary and answer
// quality — not just traffic.

func ssrfCount(m *Metrics, reason string) int64 {
	i := ssrfReasonIndex(reason)
	if i < 0 {
		return -1
	}
	return m.SSRFBlocked[i].Load()
}

func ssrfTotal(m *Metrics) int64 {
	var t int64
	for i := range m.SSRFBlocked {
		t += m.SSRFBlocked[i].Load()
	}
	return t
}

func authCount(m *Metrics, endpoint string) int64 {
	i := authEndpointIndex(endpoint)
	if i < 0 {
		return -1
	}
	return m.AuthFailures[i].Load()
}

// A blocked loopback dial, driven through the real safeDialContext exactly as
// the fetch client wires it, must increment mcp_ssrf_blocked_total under the
// address's reason class — here "loopback" — and nothing else.
func TestSSRFBlock_LiveDialIncrementsByReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	a := emptyFetchACL()
	a.metrics = &Metrics{}

	if _, err := clientFor(a).Get(srv.URL); err == nil {
		t.Fatal("expected loopback fetch to be blocked by default")
	}
	if got := ssrfCount(a.metrics, "loopback"); got != 1 {
		t.Errorf("mcp_ssrf_blocked_total{reason=loopback} = %d, want 1", got)
	}
	if got := ssrfTotal(a.metrics); got != 1 {
		t.Errorf("total SSRF blocks = %d, want exactly 1 (no other reason should fire)", got)
	}
}

// The redirect re-validation path is the second SSRF funnel and must count too:
// an open redirect to a blocked internal host is exactly the pivot the metric
// needs to make visible.
func TestSSRFBlock_RedirectIncrementsCounter(t *testing.T) {
	a, _ := newFetchACL([]string{"127.0.0.1:80"}, nil) // entry host allowed
	a.metrics = &Metrics{}

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/admin", nil)
	if err := a.safeCheckRedirect(req, nil); err == nil {
		t.Fatal("redirect to non-allow-listed loopback host should be blocked")
	}
	if got := ssrfCount(a.metrics, "loopback"); got != 1 {
		t.Errorf("redirect block: mcp_ssrf_blocked_total{reason=loopback} = %d, want 1", got)
	}
}

// A DNS resolution failure is not an SSRF block and must not be counted as one:
// countSSRFBlock only reacts to *blockedAddrError, so a resolve error leaves
// every reason at zero. This keeps the metric a true measure of the boundary
// firing, not of unrelated dial failures.
func TestSSRFBlock_ResolveFailureNotCounted(t *testing.T) {
	a := emptyFetchACL()
	a.metrics = &Metrics{}

	// .invalid is reserved (RFC 6761) and never resolves.
	_, err := clientFor(a).Get("http://nonexistent.host.invalid/")
	if err == nil {
		t.Fatal("expected a dial error for an unresolvable host")
	}
	if got := ssrfTotal(a.metrics); got != 0 {
		t.Errorf("a resolve failure must not increment mcp_ssrf_blocked_total, got total %d", got)
	}
}

// Each gated surface increments mcp_auth_failures_total under its own endpoint
// label on a 401: the MCP table, the metrics gate (both its closed-when-unset
// branch and a wrong shared secret), and the health gate.
func TestAuthFailures_CountedPerEndpoint(t *testing.T) {
	mcpTok := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	metricsTok := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	healthTok := "cccccccccccccccccccccccccccccccc"
	mcpDigest := sha256.Sum256([]byte("Bearer " + mcpTok))
	metricsDigest := sha256.Sum256([]byte("Bearer " + metricsTok))
	healthDigest := sha256.Sum256([]byte("Bearer " + healthTok))

	s := &Server{config: Config{
		AuthTokens:   map[tokenDigest]string{mcpDigest: "alice"},
		MetricsToken: map[tokenDigest]struct{}{metricsDigest: {}},
		HealthToken:  map[tokenDigest]struct{}{healthDigest: {}},
	}}

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	reject := func(h http.Handler, path, authHeader string) {
		r := httptest.NewRequest("GET", path, nil)
		if authHeader != "" {
			r.Header.Set("Authorization", authHeader)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d", path, w.Code)
		}
	}

	reject(s.requireAuth(ok), "/", "Bearer wrong")               // mcp: +1
	reject(s.requireMetricsAuth(ok), "/metrics", "Bearer wrong") // metrics (shared secret): +1
	reject(s.requireHealthAuth(ok), "/health", "Bearer wrong")   // health: +1

	if got := authCount(&s.metrics, "mcp"); got != 1 {
		t.Errorf("mcp_auth_failures_total{endpoint=mcp} = %d, want 1", got)
	}
	if got := authCount(&s.metrics, "metrics"); got != 1 {
		t.Errorf("mcp_auth_failures_total{endpoint=metrics} = %d, want 1", got)
	}
	if got := authCount(&s.metrics, "health"); got != 1 {
		t.Errorf("mcp_auth_failures_total{endpoint=health} = %d, want 1", got)
	}

	// A successful auth must not increment.
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Header.Set("Authorization", "Bearer "+metricsTok)
	w := httptest.NewRecorder()
	s.requireMetricsAuth(ok).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("valid metrics token: expected 200, got %d", w.Code)
	}
	if got := authCount(&s.metrics, "metrics"); got != 1 {
		t.Errorf("a successful auth must not increment; metrics count = %d, want 1", got)
	}
}

// The closed-when-unset metrics branch (MCP_METRICS_TOKEN not configured) is a
// distinct 401 path from the shared-secret mismatch above, and must also count
// under endpoint="metrics".
func TestAuthFailures_MetricsClosedBranchCounted(t *testing.T) {
	s := &Server{config: Config{}} // no metrics token → endpoint closed
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	w := httptest.NewRecorder()
	s.requireMetricsAuth(ok).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 from closed metrics endpoint, got %d", w.Code)
	}
	if got := authCount(&s.metrics, "metrics"); got != 1 {
		t.Errorf("closed metrics branch: endpoint=metrics count = %d, want 1", got)
	}
}

// A degraded search (HTTP 200 with unresponsive engines) increments
// mcp_search_degraded_total once. It is not an error, so SearchErrors must stay
// zero — the whole reason this counter exists.
func TestSearchDegraded_IncrementsCounter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"title":"T","url":"https://example.com","content":"C"}],
		                        "unresponsive_engines":` + searxUnresponsiveWire + `}`))
	}))
	defer srv.Close()

	s := &Server{config: Config{SearxngURL: srv.URL}, client: srv.Client()}

	// Silence the WARN line this path emits so it doesn't clutter test output.
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	_, err := s.search(context.Background(), "q", 1, "", "all", "", 0, "")
	slog.SetDefault(old)
	if err != nil {
		t.Fatalf("a degraded search is still successful: %v", err)
	}

	if got := s.metrics.SearchDegraded.Load(); got != 1 {
		t.Errorf("mcp_search_degraded_total = %d, want 1", got)
	}
	if got := s.metrics.SearchErrors.Load(); got != 0 {
		t.Errorf("a degraded search must not be counted as an error; SearchErrors = %d, want 0", got)
	}
}

// A healthy search leaves the degraded counter at zero.
func TestSearchDegraded_HealthyDoesNotIncrement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"title":"T","url":"https://example.com","content":"C"}],
		                        "unresponsive_engines":[]}`))
	}))
	defer srv.Close()

	s := &Server{config: Config{SearxngURL: srv.URL}, client: srv.Client()}
	if _, err := s.search(context.Background(), "q", 1, "", "all", "", 0, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := s.metrics.SearchDegraded.Load(); got != 0 {
		t.Errorf("healthy search: mcp_search_degraded_total = %d, want 0", got)
	}
}

// The exposition must carry all three series with the right TYPE line, every
// fixed label value present (including the zero ones — a scraper needs the
// series to exist before the first event), and the driven values.
func TestServeMetrics_ExposesGuardrailSeries(t *testing.T) {
	s := NewServer(Config{CacheMaxEntries: 1})
	s.metrics.recordSSRFBlock("loopback")
	s.metrics.recordSSRFBlock("private")
	s.metrics.recordSSRFBlock("private")
	s.metrics.recordAuthFailure("mcp")
	s.metrics.recordAuthFailure("metrics")
	s.metrics.SearchDegraded.Add(3)

	rec := httptest.NewRecorder()
	s.ServeMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		"# TYPE mcp_ssrf_blocked_total counter\n",
		`mcp_ssrf_blocked_total{reason="loopback"} 1` + "\n",
		`mcp_ssrf_blocked_total{reason="private"} 2` + "\n",
		`mcp_ssrf_blocked_total{reason="reserved"} 0` + "\n", // zero series still emitted
		"# TYPE mcp_auth_failures_total counter\n",
		`mcp_auth_failures_total{endpoint="mcp"} 1` + "\n",
		`mcp_auth_failures_total{endpoint="metrics"} 1` + "\n",
		`mcp_auth_failures_total{endpoint="health"} 0` + "\n",
		"# TYPE mcp_search_degraded_total counter\n",
		"mcp_search_degraded_total 3\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q in:\n%s", want, body)
		}
	}
}

// An unrecognised reason / endpoint is dropped rather than minting a bogus
// series — the property that keeps the label sets closed if a future address
// class or endpoint is added upstream without a matching label here.
func TestGuardrailRecorders_IgnoreUnknownLabels(t *testing.T) {
	var m Metrics
	m.recordSSRFBlock("not-a-real-reason")
	m.recordAuthFailure("not-a-real-endpoint")
	if got := ssrfTotal(&m); got != 0 {
		t.Errorf("unknown SSRF reason must be dropped, got total %d", got)
	}
	var authTotal int64
	for i := range m.AuthFailures {
		authTotal += m.AuthFailures[i].Load()
	}
	if authTotal != 0 {
		t.Errorf("unknown auth endpoint must be dropped, got total %d", authTotal)
	}
}
