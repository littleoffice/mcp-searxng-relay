package main

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A valid MCP_METRICS_TOKEN parses into a single-entry digest set whose key is
// the SHA-256 of the full "Bearer "+token header value — the same scheme
// requireMetricsAuth looks up against.
func TestParseMetricsToken_Valid(t *testing.T) {
	tok := "0123456789abcdef0123456789abcdef" // 32 chars, meets the minimum
	t.Setenv("MCP_METRICS_TOKEN", tok)

	m, err := parseMetricsToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m) != 1 {
		t.Fatalf("expected 1 digest, got %d", len(m))
	}
	want := sha256.Sum256([]byte("Bearer " + tok))
	if _, ok := m[want]; !ok {
		t.Errorf("digest set does not contain the expected Bearer-header digest")
	}
}

// Unset yields a nil set and no error; requireMetricsAuth turns that into a
// closed endpoint (see TestRequireMetricsAuth_ClosedWhenUnset).
func TestParseMetricsToken_UnsetIsNil(t *testing.T) {
	t.Setenv("MCP_METRICS_TOKEN", "")

	m, err := parseMetricsToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Errorf("expected nil digest set when unset, got %v", m)
	}
}

// A too-short token fails startup rather than being silently accepted, matching
// the stance taken for the MCP and health tokens.
func TestParseMetricsToken_TooShortFails(t *testing.T) {
	t.Setenv("MCP_METRICS_TOKEN", "short")

	if _, err := parseMetricsToken(); err == nil {
		t.Fatalf("expected error for a token below the minimum length, got nil")
	}
}

// The error names the variable that was misconfigured, so an operator setting
// both shared secrets does not have to guess which one is wrong.
func TestParseSharedSecretToken_ErrorNamesTheVariable(t *testing.T) {
	t.Setenv("MCP_METRICS_TOKEN", "short")
	_, err := parseMetricsToken()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "MCP_METRICS_TOKEN") {
		t.Errorf("error should name MCP_METRICS_TOKEN, got: %v", err)
	}
}

// With no metrics token configured the endpoint is CLOSED — it does not fall
// back to the MCP token table. A valid MCP token, a wrong token, and no token
// at all all get 401, and the handler never runs. This is the property that
// makes the separation a boundary rather than an opt-in: it holds in
// deployments that have not been reconfigured, not only in the ones that have.
func TestRequireMetricsAuth_ClosedWhenUnset(t *testing.T) {
	mcpTok := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mcpDigest := sha256.Sum256([]byte("Bearer " + mcpTok))
	s := &Server{config: Config{
		AuthTokens: map[tokenDigest]string{mcpDigest: "alice"},
		// MetricsToken deliberately nil
	}}

	var called bool
	h := s.requireMetricsAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, authHeader := range []string{
		"Bearer " + mcpTok, // a perfectly valid MCP tenant token
		"Bearer nonsense-value-that-matches-nothing",
		"", // no credential at all
	} {
		called = false
		r := httptest.NewRequest("GET", "/metrics", nil)
		if authHeader != "" {
			r.Header.Set("Authorization", authHeader)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("no metrics token configured, header %q: expected 401, got %d", authHeader, w.Code)
		}
		if called {
			t.Errorf("no metrics token configured, header %q: handler must not run", authHeader)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != `Bearer realm="metrics"` {
			t.Errorf("no metrics token configured, header %q: unexpected challenge %q", authHeader, got)
		}
	}
}

// The health token keeps its opposite default: unset leaves /health OPEN.
// Asserted here, next to the metrics case, because the two endpoints
// deliberately disagree and a future refactor that "harmonises" them would
// either close a load balancer's probe or reopen the metrics disclosure.
func TestSharedSecretDefaults_HealthOpenMetricsClosed(t *testing.T) {
	s := &Server{config: Config{}} // neither token configured
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	probe := func(h http.Handler, path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w.Code
	}

	if code := probe(s.requireHealthAuth(ok), "/health"); code != http.StatusOK {
		t.Errorf("/health with no token should stay open, got %d", code)
	}
	if code := probe(s.requireMetricsAuth(ok), "/metrics"); code != http.StatusUnauthorized {
		t.Errorf("/metrics with no token should be closed, got %d", code)
	}
}

// The finding this closes: an ordinary MCP tenant token does not open
// /metrics, so a tenant cannot read mcp_fetches_by_domain_total and learn
// which hosts every other tenant fetched. Only the dedicated token does.
func TestRequireMetricsAuth_MCPTokenRejected(t *testing.T) {
	mcpTok := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	metricsTok := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	mcpDigest := sha256.Sum256([]byte("Bearer " + mcpTok))
	metricsDigest := sha256.Sum256([]byte("Bearer " + metricsTok))

	s := &Server{config: Config{
		AuthTokens:   map[tokenDigest]string{mcpDigest: "alice"},
		MetricsToken: map[tokenDigest]struct{}{metricsDigest: {}},
	}}

	var called bool
	h := s.requireMetricsAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	do := func(authHeader string) *httptest.ResponseRecorder {
		called = false
		r := httptest.NewRequest("GET", "/metrics", nil)
		if authHeader != "" {
			r.Header.Set("Authorization", authHeader)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// A tenant's MCP token must NOT open /metrics any more.
	w := do("Bearer " + mcpTok)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("MCP tenant token: expected 401, got %d", w.Code)
	}
	if called {
		t.Error("MCP tenant token: handler must not run")
	}

	// The dedicated metrics token does.
	if w := do("Bearer " + metricsTok); w.Code != http.StatusOK || !called {
		t.Errorf("metrics token: expected 200 with handler run, got %d (called=%v)", w.Code, called)
	}

	// A missing header gets 401 plus a challenge naming the metrics realm.
	w = do("")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing token: expected 401, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer realm="metrics"` {
		t.Errorf("missing token: unexpected challenge %q", got)
	}
}

// The two shared secrets are independent: a health token must not open
// /metrics, and a metrics token must not open /health.
func TestSharedSecrets_DoNotCrossEndpoints(t *testing.T) {
	healthTok := "cccccccccccccccccccccccccccccccc"
	metricsTok := "dddddddddddddddddddddddddddddddd"
	healthDigest := sha256.Sum256([]byte("Bearer " + healthTok))
	metricsDigest := sha256.Sum256([]byte("Bearer " + metricsTok))

	s := &Server{config: Config{
		HealthToken:  map[tokenDigest]struct{}{healthDigest: {}},
		MetricsToken: map[tokenDigest]struct{}{metricsDigest: {}},
	}}

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	probe := func(h http.Handler, path, tok string) int {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	if code := probe(s.requireMetricsAuth(ok), "/metrics", healthTok); code != http.StatusUnauthorized {
		t.Errorf("health token on /metrics: expected 401, got %d", code)
	}
	if code := probe(s.requireHealthAuth(ok), "/health", metricsTok); code != http.StatusUnauthorized {
		t.Errorf("metrics token on /health: expected 401, got %d", code)
	}
	// Each opens its own endpoint.
	if code := probe(s.requireMetricsAuth(ok), "/metrics", metricsTok); code != http.StatusOK {
		t.Errorf("metrics token on /metrics: expected 200, got %d", code)
	}
	if code := probe(s.requireHealthAuth(ok), "/health", healthTok); code != http.StatusOK {
		t.Errorf("health token on /health: expected 200, got %d", code)
	}
}

// The banner must not describe stdio as having an endpoint it does not serve,
// and must say plainly when /metrics is on the shared table.
func TestMetricsAuthLabel(t *testing.T) {
	if got := metricsAuthLabel("stdio", false); !strings.Contains(got, "n/a") {
		t.Errorf("stdio should report n/a, got %q", got)
	}
	if got := metricsAuthLabel("streamable-http", true); !strings.Contains(got, "MCP_METRICS_TOKEN") {
		t.Errorf("dedicated label should name the variable, got %q", got)
	}
	if got := metricsAuthLabel("streamable-http", false); !strings.Contains(got, "CLOSED") {
		t.Errorf("unset label should say the endpoint is closed, got %q", got)
	}
}
