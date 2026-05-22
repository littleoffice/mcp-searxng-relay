package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// maxSessions is a soft cap on the number of concurrent HTTP sessions.
// Initialize requests beyond this limit are rejected with 503 to prevent
// the SDK's internal session map from growing without bound.
const maxSessions = 1000

// ── identity context plumbing ─────────────────────────────────────────────────
//
// After requireAuth matches a request to a configured token, it stuffs the
// associated identity into the request context.  Tool handlers and the
// InitializedHandler pull it back out via identityFromContext to attach
// "who did this" to their log lines — the join key for audit forensics.

// identityCtxKey is unexported so external packages can't accidentally
// collide with this key.  The empty-struct pattern (rather than a string)
// is the idiomatic Go way to make context keys uniquely typed.
type identityCtxKey struct{}

// withIdentity returns a child context carrying identity.  Used by
// requireAuth on each authenticated request.
func withIdentity(ctx context.Context, identity string) context.Context {
	return context.WithValue(ctx, identityCtxKey{}, identity)
}

// identityFromContext returns the identity attached by requireAuth, or
// "" if the context carries none (stdio mode, or an unauthenticated path
// like /health).  Logs treat "" as "anonymous / not applicable" — distinct
// from a real identity that just happens to be empty, which addAuthToken
// rejects at startup.
func identityFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(identityCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// ── HTTP wrappers ─────────────────────────────────────────────────────────────
//
// The MCP Streamable HTTP transport (POST/GET/DELETE on /, SSE responses,
// session ID assignment, JSON-RPC framing) is fully owned by
// mcp.StreamableHTTPHandler. This file contributes only:
//
//   - bearer-token authentication, possibly against multiple tokens
//   - a soft session cap on initialize requests
//   - an unauthenticated /health probe with cached upstream check
//   - Prometheus /metrics behind auth
//
// /metrics is registered in main.go alongside the SDK handler.

// requireAuth wraps a handler with bearer-token authentication against the
// configured token table.
//
// The Authorization header value is run through SHA-256 once and looked up
// in cfg.AuthTokens, which is itself keyed by the SHA-256 of the expected
// "Bearer "+token strings.  Two reasons for hashing both sides:
//
//   - The lookup operates on fixed-length 32-byte keys, so it cannot leak
//     token length via timing (a bare equality check on the raw header
//     would short-circuit at the first differing byte).
//   - Storing only digests means the raw tokens never sit in process
//     memory after parseAuthTokens returns; the only path to recover them
//     is from the env / token file, which is the operator's domain.
//
// Map lookup itself is O(1) on a hash already designed for uniform
// distribution, so the only timing channel left — bucket walk on
// collision — is bounded by Go's map implementation and not by anything
// an attacker can probe with the inputs they control.
//
// On success the matched identity is attached to the request context for
// downstream handlers to log.  On failure: 401 with WWW-Authenticate per
// RFC 6750 §3, and a warn-level log including the remote address (but
// never the offered Authorization header — that would leak guesses).
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.config.AuthTokens) > 0 {
			got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
			identity, ok := s.config.AuthTokens[got]
			if !ok {
				slog.Warn("unauthorized request",
					"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
				w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			r = r.WithContext(withIdentity(r.Context(), identity))
		}
		next.ServeHTTP(w, r)
	})
}

// limitSessions rejects new initialize requests when the session cap is
// reached. We identify initialize requests heuristically: a POST with no
// Mcp-Session-Id header, since the SDK assigns the session ID and clients
// only echo it back on subsequent requests.
//
// This is a soft cap — concurrent initialize requests can briefly slip past
// it — but it bounds runaway growth, which is what we want.
func (s *Server) limitSessions(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.Header.Get("Mcp-Session-Id") == "" {
			if n := s.sessionCount(); n >= maxSessions {
				slog.Warn("session cap reached, rejecting initialize",
					"active", n, "cap", maxSessions)
				http.Error(w, "too many active sessions", http.StatusServiceUnavailable)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// logRequests logs each incoming HTTP request at debug level.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"session_id", r.Header.Get("Mcp-Session-Id"))
		next.ServeHTTP(w, r)
	})
}

// ── /health ───────────────────────────────────────────────────────────────────

// handleHealth is an unauthenticated liveness + readiness probe.
// It checks reachability of the upstream SearXNG instance and returns:
//
//	200 OK        — server is running and SearXNG is reachable
//	503 Unavailable — SearXNG probe failed
//
// The probe result is cached for 10 seconds so load-balancer polls do not
// hammer the upstream.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	const probeTTL = 10 * time.Second

	s.healthMu.Lock()
	if time.Since(s.healthChecked) < probeTTL {
		ok := s.healthOK
		s.healthMu.Unlock()
		s.writeHealthResponse(w, ok)
		return
	}
	s.healthMu.Unlock()

	// Probe SearXNG with a short timeout so a slow upstream doesn't stall
	// the health check indefinitely.
	ctx := r.Context()
	probeReq, err := http.NewRequestWithContext(ctx, http.MethodGet, s.config.SearxngURL, nil)
	ok := false
	if err == nil {
		probeClient := &http.Client{Timeout: 5 * time.Second}
		resp, err := probeClient.Do(probeReq)
		if err == nil {
			resp.Body.Close()
			ok = resp.StatusCode < 500
		}
	}

	s.healthMu.Lock()
	s.healthOK = ok
	s.healthChecked = time.Now()
	s.healthMu.Unlock()

	if !ok {
		slog.Warn("health probe: SearXNG unreachable", "url", s.config.SearxngURL)
	}
	s.writeHealthResponse(w, ok)
}

func (s *Server) writeHealthResponse(w http.ResponseWriter, ok bool) {
	w.Header().Set("Content-Type", "application/json")
	if ok {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","searxng":"reachable"}`+"\n")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, `{"status":"degraded","searxng":"unreachable"}`+"\n")
	}
}

// ── /fence/public-key ─────────────────────────────────────────────────────────

// handleFencePublicKey returns the Ed25519 public key used to sign fenced
// tool responses, so a future fence-verifying MCP client (the paper's
// "security gateway") can validate signatures.
//
// The endpoint is intentionally unauthenticated: a public key is, by
// definition, public.  The fingerprint is included for cross-checking
// against the startup-banner value operators have on hand.
//
// The key rotates on every server restart — operators wanting cross-restart
// continuity should run behind a process supervisor that holds a long-lived
// key (see fence.go).
func (s *Server) handleFencePublicKey(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"version":%q,"algorithm":"Ed25519","publicKey":%q,"fingerprint":%q}`+"\n",
		fenceFormatVersion,
		fencePublicKeyBase64(s.fencePublicKey),
		fenceKeyFingerprint(s.fencePublicKey))
}
