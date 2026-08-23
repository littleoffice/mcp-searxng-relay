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

// sessionIDHeader is the MCP Streamable HTTP session header.  The SDK owns
// this header on the wire; we read it in three places that are all our own
// concerns (the initialize heuristic in limitSessions, debug request logs, and
// the stateless correlation ID below) and never write it.
const sessionIDHeader = "Mcp-Session-Id"

// maxClientSessionIDLen bounds the client-asserted conversation ID we are
// willing to carry.  The SDK's own IDs are 26-character crypto-random strings;
// 128 leaves generous room for a client with a different scheme while keeping
// the value short enough that it cannot bloat every log line it appears in.
const maxClientSessionIDLen = 128

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

// ── stateless conversation correlation ──────────────────────────────────────
//
// Under MCP_STATELESS the SDK no longer reads Mcp-Session-Id at all: as of
// go-sdk v1.7.0 a stateless server "does not read or set" the header, so
// req.Session.ID() is empty for every request.  Before v1.7.0 the SDK echoed
// the client's value back through the session, and this relay used it for two
// things — the session_id field in audit logs, and the second half of the
// per-caller key in history.go.
//
// Losing it is not a security problem: identity is the server-validated half
// and is what keeps tenants apart.  It is a correctness problem for the source
// ledger.  Two conversations sharing one token now land in one drawer, evicting
// each other's sources and reading each other's URLs back — precisely the
// "the model cannot tell which entries belong to the exchange it is currently
// in" failure that history.go's Lifetime note warns about.
//
// So the relay reads the header itself, in stateless mode only.  What this
// value is has not changed: a client-asserted string, useful for correlation
// and worthless as an assertion of who the caller is.  What changed is who
// reads it — it is now this relay's deliberate choice rather than an SDK
// implementation detail we inherited, which is the honest way to carry a
// property the MCP spec is moving away from (SEP-2567).  If clients stop
// sending the header, this degrades back to an empty session ID rather than
// breaking.
//
// It is deliberately NOT consulted in stateful mode.  There the SDK issues a
// real, validated ID, and the "true sessionless" configuration documented in
// the README (ServerOptions.GetSessionID returning "") is an operator asking
// for no session IDs in their logs at all — a fallback that reinstated
// client-supplied ones would quietly overturn that request.

// clientSessionCtxKey carries the client-asserted conversation ID read off the
// request in stateless mode.  Distinct from sessionCtxKey, which carries
// whatever the tool handler resolved (SDK-issued, or this, or neither).
type clientSessionCtxKey struct{}

// withClientSessionID returns a child context carrying a validated
// client-asserted conversation ID.
func withClientSessionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, clientSessionCtxKey{}, id)
}

// clientSessionIDFromContext returns the validated client-asserted
// conversation ID, or "" when the request carried none (every stateful
// request, stdio, and any stateless request whose header failed validation).
func clientSessionIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(clientSessionCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// sanitizeClientSessionID returns id when it is safe to carry, and "" when it
// is not.
//
// The value reaches two places that make its shape matter: a cache key in
// history.go, and a log field.  Rejection is total rather than by truncation —
// truncating would map two distinct conversations onto one key, which is the
// exact confusion this ID exists to prevent, and would do it silently.
//
// The accepted set is printable ASCII with no spaces: broad enough for any
// sane session-ID scheme (the SDK's own is base32), narrow enough that a value
// cannot carry control characters, newlines, or non-UTF-8 bytes into a log
// line or a metrics label.
func sanitizeClientSessionID(id string) string {
	if id == "" || len(id) > maxClientSessionIDLen {
		return ""
	}
	for i := 0; i < len(id); i++ {
		if id[i] < '!' || id[i] > '~' {
			return ""
		}
	}
	return id
}

// sessionCtxKey carries the MCP session ID the same way identityCtxKey
// carries the identity.  Unlike identity, it is attached by the tool
// handlers rather than by requireAuth: the SDK assigns session IDs, so the
// value is not known until a CallToolRequest exists.
type sessionCtxKey struct{}

// withSessionID returns a child context carrying the MCP session ID.  Tool
// handlers call this once at entry so that everything downstream of them —
// the shared fetch pipeline in particular — can emit fully attributed log
// lines without threading the request through every signature.
func withSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, sessionID)
}

// sessionIDFromContext returns the session ID attached by a tool handler,
// or "" when the context carries none (stdio mode, unit tests constructing
// a request without a session, or a non-tool code path).
func sessionIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(sessionCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// callerLogger returns the default logger pre-bound with the caller
// attribution attrs — "identity" and "session_id".
//
// Every log line emitted while serving a tool call should come from this
// logger rather than from slog directly.  Attribution is what makes the
// audit log joinable: without it a line records that a URL was fetched but
// not on whose behalf, which is exactly the question an incident review
// asks.  Both fields degrade to "" rather than being omitted, so the key
// set is stable across transports and log processors can rely on it.
func callerLogger(ctx context.Context) *slog.Logger {
	return slog.Default().With(
		"identity", identityFromContext(ctx),
		"session_id", sessionIDFromContext(ctx),
	)
}

// ── HTTP wrappers ─────────────────────────────────────────────────────────────
//
// The MCP Streamable HTTP transport (POST/GET/DELETE on /, SSE responses,
// session ID assignment, JSON-RPC framing) is fully owned by
// mcp.StreamableHTTPHandler. This file contributes only:
//
//   - bearer-token authentication, possibly against multiple tokens
//   - a soft session cap on initialize requests
//   - a /health probe (open by default, optionally gated by MCP_HEALTH_TOKEN)
//     with a cached upstream check
//   - Prometheus /metrics behind its own MCP_METRICS_TOKEN (401 when unset)
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

// requireSharedSecret wraps next with a check against a single-shared-secret
// digest set (see parseSharedSecretToken). Used by the /health and /metrics
// gates, which authenticate a probe or a scraper rather than a caller and so
// have no identity to attach to the context.
//
// The check mirrors requireAuth exactly: a single SHA-256 of the full header
// value looked up in a set keyed by the digest of "Bearer "+token, so it
// carries the same timing-safe property (fixed 32-byte comparison, no
// short-circuit on the first differing byte) and never logs the offered
// header. On failure it returns 401 with a WWW-Authenticate challenge naming
// realm, and a warn line carrying logMsg and the remote address.
func requireSharedSecret(
	tokens map[tokenDigest]struct{}, realm, logMsg string, next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if _, ok := tokens[got]; !ok {
			slog.Warn(logMsg, "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireHealthAuth is the /health-dedicated auth check. When a health token
// is configured (len(cfg.HealthToken) > 0, from MCP_HEALTH_TOKEN) it verifies
// the request's Authorization header against it — a separate secret from the
// MCP bearer tokens in cfg.AuthTokens, because the health probe and the MCP
// endpoint are two different trust domains and must not share a credential.
//
// When no health token is configured the endpoint is open — the historical
// behaviour, preserved so existing deployments keep working. Operators are
// encouraged to set MCP_HEALTH_TOKEN whenever /health is reachable beyond the
// local host; see the README for the load-balancer / Kubernetes caveat.
func (s *Server) requireHealthAuth(next http.Handler) http.Handler {
	if len(s.config.HealthToken) == 0 {
		return next
	}
	return requireSharedSecret(s.config.HealthToken, "health", "unauthorized health request", next)
}

// requireMetricsAuth is the /metrics-dedicated auth check.  MCP_METRICS_TOKEN
// is REQUIRED: with none configured the endpoint answers 401 to everyone,
// including callers holding a valid MCP token.
//
// Why /metrics needs a credential of its own: it serves
// mcp_fetches_by_domain_total, which names up to 512 destination hostnames the
// relay has fetched — across every caller.  Gated on the shared MCP token
// table, that makes each tenant's browsing targets readable by every other
// tenant, and on a relay with FETCH_ALLOWED_HOSTS configured those hostnames
// describe the internal estate.  A scraper is not a tenant and should not be
// holding a tenant's credential; a tenant is not a scraper and should not be
// able to read the fleet's egress profile.
//
// Closed rather than falling back to the MCP token table.  A fallback reads as
// the safe choice — nothing breaks on upgrade — but it means the separation
// this endpoint exists to draw silently does not hold wherever the operator
// has not opted in, which is every deployment that has not yet read the
// release note.  A security boundary that is only present when configured is
// not a boundary; 401 until a credential exists is the honest default, and it
// fails in the direction that discloses nothing.
//
// The cost is real and deliberate: an existing Prometheus scraper starts
// getting 401s on upgrade until MCP_METRICS_TOKEN is set and its scrape config
// updated.  runHTTP logs a warn line at startup when the token is absent so
// the reason is in the logs before the first scrape fails, and the startup
// banner says the endpoint is closed.
//
// The empty-map lookup in requireSharedSecret would already reject everything,
// but the branch is written out so the closed state is a stated decision at
// the call site rather than an emergent property of an empty map.
func (s *Server) requireMetricsAuth(next http.Handler) http.Handler {
	if len(s.config.MetricsToken) == 0 {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Warn("metrics request rejected: MCP_METRICS_TOKEN is not configured",
				"remote", r.RemoteAddr,
				"hint", "set MCP_METRICS_TOKEN to a value from `openssl rand -hex 32` and give it to your scraper")
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}
	return requireSharedSecret(s.config.MetricsToken, "metrics", "unauthorized metrics request", next)
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
		if r.Method == http.MethodPost && r.Header.Get(sessionIDHeader) == "" {
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

// trackClientSession attaches the client-asserted conversation ID to the
// request context in stateless mode, so tool handlers can fall back to it when
// the SDK gives them no session ID of its own.
//
// A separate middleware rather than a few lines inside requireAuth: this is
// correlation plumbing, not authentication, and requireAuth's identity attach
// is deliberately conditional on a configured token table — a caller running
// without tokens still has conversations worth keeping apart.
func (s *Server) trackClientSession(next http.Handler) http.Handler {
	if !s.config.Stateless {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := sanitizeClientSessionID(r.Header.Get(sessionIDHeader)); id != "" {
			r = r.WithContext(withClientSessionID(r.Context(), id))
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
			"session_id", r.Header.Get(sessionIDHeader))
		next.ServeHTTP(w, r)
	})
}

// ── /health ───────────────────────────────────────────────────────────────────

// handleHealth is a liveness + readiness probe. It is open by default;
// wrapping it in requireHealthAuth (when MCP_HEALTH_TOKEN is set) gates it
// behind a bearer token. It checks reachability of the upstream SearXNG
// instance and returns:
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
// The `fingerprint` field is the same value each fence carries as its `kid`
// attribute, so a verifier can key its trusted-key set on it directly. It is
// deliberately not renamed to "kid" here: anything already parsing this
// response expects `fingerprint`.
//
// The key rotates on every server restart unless the operator supplied one
// via FENCE_SIGNING_KEY / FENCE_SIGNING_KEY_FILE, in which case it is stable
// for as long as that key is (see fence_key.go).  The startup banner says
// which of the two applies.
func (s *Server) handleFencePublicKey(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"version":%q,"algorithm":"Ed25519","publicKey":%q,"fingerprint":%q}`+"\n",
		fenceFormatVersion,
		fencePublicKeyBase64(s.fencePublicKey),
		fenceKeyFingerprint(s.fencePublicKey))
}
