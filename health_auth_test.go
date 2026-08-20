package main

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A valid MCP_HEALTH_TOKEN parses into a single-entry digest set whose key is
// the SHA-256 of the full "Bearer "+token header value — the same scheme
// requireHealthAuth looks up against.
func TestParseHealthToken_Valid(t *testing.T) {
	tok := "0123456789abcdef0123456789abcdef" // 32 chars, meets the minimum
	t.Setenv("MCP_HEALTH_TOKEN", tok)

	m, err := parseHealthToken()
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

// An unset MCP_HEALTH_TOKEN yields a nil set and no error, leaving /health
// open (the historical default).
func TestParseHealthToken_UnsetIsOpen(t *testing.T) {
	t.Setenv("MCP_HEALTH_TOKEN", "")

	m, err := parseHealthToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Errorf("expected nil digest set when unset, got %v", m)
	}
}

// A too-short token fails startup rather than being silently accepted.
func TestParseHealthToken_TooShortFails(t *testing.T) {
	t.Setenv("MCP_HEALTH_TOKEN", "short")

	if _, err := parseHealthToken(); err == nil {
		t.Fatalf("expected error for a token below the minimum length, got nil")
	}
}

// With no health token configured, requireHealthAuth is a pass-through: the
// wrapped handler runs regardless of the Authorization header.
func TestRequireHealthAuth_OpenWhenUnset(t *testing.T) {
	s := &Server{config: Config{}} // HealthToken nil
	called := false
	h := s.requireHealthAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))

	if !called {
		t.Fatalf("handler should run when no health token is configured")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// With a health token configured, the correct bearer token is admitted and a
// missing or wrong one is rejected with 401 + a WWW-Authenticate challenge.
func TestRequireHealthAuth_EnforcesToken(t *testing.T) {
	tok := "0123456789abcdef0123456789abcdef"
	digest := sha256.Sum256([]byte("Bearer " + tok))
	s := &Server{config: Config{HealthToken: map[tokenDigest]struct{}{digest: {}}}}

	var called bool
	h := s.requireHealthAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	do := func(authHeader string) *httptest.ResponseRecorder {
		called = false
		r := httptest.NewRequest("GET", "/health", nil)
		if authHeader != "" {
			r.Header.Set("Authorization", authHeader)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// Correct token → 200, handler runs.
	if w := do("Bearer " + tok); w.Code != http.StatusOK || !called {
		t.Errorf("correct token: expected 200 with handler run, got %d (called=%v)", w.Code, called)
	}

	// Missing header → 401, handler not run, challenge present.
	w := do("")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing token: expected 401, got %d", w.Code)
	}
	if called {
		t.Errorf("missing token: handler must not run")
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer realm="health"` {
		t.Errorf("missing token: unexpected challenge %q", got)
	}

	// Wrong token → 401.
	if w := do("Bearer wrong-token-value-................"); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: expected 401, got %d", w.Code)
	}
}
