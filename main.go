package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── Main ──────────────────────────────────────────────────────────────────────

// minAuthTokenLen is the minimum length for MCP_AUTH_TOKEN.  32 hex
// characters represents 128 bits of entropy, the standard floor for tokens
// that need to resist online brute-force.  Operators are expected to use
// `openssl rand -hex 32` (which yields 64 characters / 256 bits) — the
// minimum just rules out trivially weak values like "test" or "x".
const minAuthTokenLen = 32

func main() {
	// --healthcheck mode is a self-probe for use as a Docker HEALTHCHECK CMD.
	// The scratch runtime image has no shell or curl, so the binary itself
	// has to be the probe. We hit our own /health endpoint on 127.0.0.1 (the
	// server listens on :MCP_PORT, which binds all interfaces and therefore
	// always answers on loopback) and exit 0 / 1 per HEALTHCHECK convention.
	//
	// This branch is the very first thing main() does so the probe doesn't
	// open a SearXNG connection, allocate caches, or generate fence keys.
	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		runHealthCheck()
		return // unreachable — runHealthCheck calls os.Exit
	}

	cfg := configFromEnv()
	setupLogger(cfg)

	if cfg.SearxngURL == "" {
		_, _ = fmt.Fprintln(os.Stderr, "Error: SEARXNG_URL environment variable is required")
		os.Exit(1)
	}

	// Parse the auth-token table from MCP_AUTH_TOKEN / MCP_AUTH_TOKENS /
	// MCP_AUTH_TOKEN_FILE.  Any parse error fails startup with a clear
	// message — better than discovering at first request time that the
	// file has a malformed line.  An empty table is OK here; the HTTP
	// mode startup check below rejects it.
	tokens, err := parseAuthTokens()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	cfg.AuthTokens = tokens

	// Compile the fetch allow-list (FETCH_ALLOWED_HOSTS / FETCH_ALLOWED_CIDRS).
	// A malformed CIDR fails startup with a clear message — the same
	// fail-loud stance as the auth-token parser, since this is a security
	// control and a typo must not silently widen or narrow it.
	acl, err := newFetchACL(cfg.FetchAllowedHosts, cfg.FetchAllowedCIDRs)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	cfg.FetchACL = acl

	// Leave an audit line when the default public-only SSRF policy has been
	// widened, so it is obvious from the logs that the fetch tool can reach
	// internal resources and exactly which ones.
	if !acl.isEmpty() {
		slog.Warn("fetch SSRF policy widened by operator config",
			"allowed_hosts", cfg.FetchAllowedHosts,
			"allowed_cidrs", cfg.FetchAllowedCIDRs,
			"hint", "the fetch tool can now reach these internal hosts/ranges; keep the lists tight")
	}

	// Warn (don't fail) if basic-auth credentials would travel in plaintext.
	// Hard-failing would break legitimate dev/internal setups where the
	// operator knowingly accepts the risk on a trusted LAN; an audit-trail
	// log line is the right middle ground.
	if (cfg.AuthUsername != "" || cfg.AuthPassword != "") &&
		strings.HasPrefix(cfg.SearxngURL, "http://") {
		slog.Warn("SearXNG basic-auth credentials will be sent in plaintext",
			"searxng_url", cfg.SearxngURL,
			"hint", "use https:// or run the upstream behind TLS termination")
	}

	server := NewServer(cfg)

	if port := os.Getenv("MCP_PORT"); port != "" {
		runHTTP(cfg, server, port)
	} else {
		runStdio(server)
	}
}

// runStdio runs the MCP server over stdin/stdout.
//
// The SDK's StdioTransport does the line-delimited JSON-RPC framing for us;
// Server.Run blocks until the client closes stdin or the context is cancelled.
func runStdio(server *Server) {
	logConfig(server, "stdio", "")

	// We pass context.Background() because stdio sessions terminate naturally
	// on EOF; there is no signal we want to forward, matching the original
	// transport's behaviour.
	if err := server.mcpServer.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		slog.Error("stdio server error", "error", err)
		os.Exit(1)
	}
}

// runHealthCheck performs a single GET against the server's own /health
// endpoint on loopback and exits 0 for healthy, 1 for unhealthy. It's the
// implementation behind the `--healthcheck` CLI flag used by Docker
// HEALTHCHECK; the scratch base image has no shell or wget, so the binary
// has to be its own probe.
//
// The probe deliberately does very little: no logging setup, no config
// validation beyond MCP_PORT, and a short hard timeout. A frequently-run
// HEALTHCHECK that allocates structures or talks to SearXNG would amplify
// the existing concerns about /health (see audit finding #10). Here we
// just round-trip the local HTTP server.
func runHealthCheck() {
	port := os.Getenv("MCP_PORT")
	if port == "" {
		// stdio mode has no /health endpoint; treat as unhealthy. In practice
		// Docker HEALTHCHECK only fires for long-running services, but a
		// misconfigured Compose file shouldn't silently report healthy.
		_, _ = fmt.Fprintln(os.Stderr, "healthcheck: MCP_PORT is not set")
		os.Exit(1)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		os.Exit(1)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(os.Stderr, "healthcheck: HTTP %d\n", resp.StatusCode)
		os.Exit(1)
	}
	os.Exit(0)
}

// runHTTP runs the MCP server over the Streamable HTTP transport, plus
// /health (unauthenticated) and /metrics (authenticated).
func runHTTP(cfg Config, server *Server, port string) {
	// At least one auth token is mandatory in HTTP mode: the server is
	// network-accessible and there is no other authentication layer built
	// in.  parseAuthTokens already validated the 32-character minimum on
	// every token it accepted, so we only need to check the table isn't
	// empty here.
	if len(cfg.AuthTokens) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "Error: at least one auth token is required when MCP_PORT is set")
		_, _ = fmt.Fprintln(os.Stderr, "       Configure one of:")
		_, _ = fmt.Fprintln(os.Stderr, "         MCP_AUTH_TOKEN=<token>                     (single-tenant)")
		_, _ = fmt.Fprintln(os.Stderr, "         MCP_AUTH_TOKENS=alice:tok1,bob:tok2        (small static fleet)")
		_, _ = fmt.Fprintln(os.Stderr, "         MCP_AUTH_TOKEN_FILE=/etc/mcp/tokens         (larger / rotated set)")
		_, _ = fmt.Fprintln(os.Stderr, "       Generate strong tokens with:  openssl rand -hex 32")
		os.Exit(1)
	}

	logConfig(server, "streamable-http", port)

	// The SDK's StreamableHTTPHandler implements the full transport:
	// POST/GET/DELETE on the same path, SSE responses for streaming, session
	// IDs in Mcp-Session-Id, JSON-RPC framing.  We pass a constant getServer
	// closure since all clients share one *mcp.Server (sessions are tracked
	// per-request internally).
	//
	// Cross-origin / CSRF protection: SDK v1.4.1+ wraps the handler in Go's
	// net/http.CrossOriginProtection by default.  That rejects POSTs whose
	// Sec-Fetch-Site / Origin headers indicate a cross-origin browser request,
	// and rejects POSTs without Content-Type: application/json (CVE-2026-33252,
	// fixed in go-sdk a433a83).  Non-browser API clients (curl, Go http.Client,
	// AI agent traffic) send neither Sec-Fetch-Site nor Origin and are allowed
	// through — so legitimate remote-agent use is unaffected.
	//
	// Stateless toggle: when cfg.Stateless is true, the SDK skips session-ID
	// validation and treats each request as having a fresh, temporary
	// session.  Useful for personal-use deployments where you want the
	// server to survive restarts without forcing the agent to reconnect.
	// At the cost of losing the cross-request session-ID join key for
	// audit logs — the README discusses the trade-off in detail.
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server.mcpServer },
		&mcp.StreamableHTTPOptions{Stateless: cfg.Stateless},
	)

	mux := http.NewServeMux()
	// MCP root: per-caller rate limit → bearer auth → soft session cap → SDK handler.
	//
	// Rate limit sits on the OUTSIDE so unauthenticated brute-force traffic
	// from a single IP gets throttled at the network edge instead of
	// burning unbounded auth-check cycles.  callerKey() does its own
	// Authorization-header hash lookup (mirroring requireAuth), so authed
	// callers still get per-identity buckets; unauthed and wrong-token
	// callers fall back to per-IP buckets.  See rate_limit.go.
	//
	// Cost of this ordering: authed requests hash the Authorization header
	// twice (once in callerKey, once in requireAuth).  Two SHA-256s of a
	// ~70-byte input — negligible compared to anything else on this path.
	mux.Handle("/", server.rateLimit(server.requireAuth(server.limitSessions(mcpHandler))))
	// /health is intentionally unauthenticated for load balancers, and
	// intentionally NOT rate-limited so a polling LB never gets 429.
	mux.HandleFunc("/health", server.handleHealth)
	// /fence/public-key is intentionally unauthenticated — public keys are public.
	mux.HandleFunc("/fence/public-key", server.handleFencePublicKey)
	// /metrics is behind the same bearer token as the MCP endpoint.  We
	// deliberately do NOT rate-limit it: monitoring scrapers poll on a
	// schedule that's already low-rate, and a 429 from /metrics would
	// produce gaps in Prometheus that look identical to outages.  An
	// abusive scraper is better contained by withholding the token.
	mux.Handle("/metrics", server.requireAuth(http.HandlerFunc(server.ServeMetrics)))

	srv := &http.Server{
		Addr:        ":" + port,
		Handler:     server.logRequests(mux),
		ReadTimeout: 30 * time.Second,
		// WriteTimeout is left at 0 (disabled): the SDK manages SSE streams
		// and sets per-connection deadlines as appropriate. A server-level
		// deadline would prematurely close long-lived event streams.
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	// ctx is cancelled when SIGTERM or SIGINT is received.
	// stop restores default signal handling once we are done with it.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// In stateful mode, run the idle-session janitor.  It walks the SDK's
	// live session set every 5 minutes and closes sessions older than 24h,
	// preventing a buggy or malicious client from accumulating sessions up
	// to the maxSessions soft cap.  No-op in stateless mode (no sessions
	// to reap) so we just don't bother starting it.
	if !cfg.Stateless {
		go server.runSessionJanitor(ctx)
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Block until a termination signal arrives.
	<-ctx.Done()
	stop() // restore default signal behaviour so a second signal exits immediately

	slog.Info("shutdown signal received, draining connections")

	// Give in-flight requests up to 30 seconds to finish.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	slog.Info("server stopped cleanly")
}

// ── Startup banner ────────────────────────────────────────────────────────────

// logConfig prints a formatted startup banner to stderr.
// It bypasses slog intentionally — slog would prefix every line with
// a timestamp, destroying the formatting.
func logConfig(server *Server, mode, port string) {
	cfg := server.config
	addr := ""
	if port != "" {
		addr = ":" + port
	}

	row := func(label, value string) string {
		return fmt.Sprintf("%-16s %s", label, value)
	}

	// The title is a banner header, not a table row — it's printed in its
	// own block above the key/value rows so it doesn't have to align with
	// the value column.
	title := fmt.Sprintf("%s %s", projectName, ServerVersion)

	rows := []string{
		row("mode", mode),
	}
	if addr != "" {
		rows = append(rows, row("address", addr))
	}
	rows = append(rows,
		row("searxng", cfg.SearxngURL),
	)
	if cfg.AuthUsername != "" {
		rows = append(rows, row("username", cfg.AuthUsername))
	}
	rows = append(rows,
		row("password", redactSecret(cfg.AuthPassword)),
		row("user-agent", cfg.UserAgent),
		row("cache ttl", cfg.CacheTTL.String()),
		row("cache entries", fmt.Sprintf("%d max", cfg.CacheMaxEntries)),
		row("body limit", fmt.Sprintf("%d bytes", cfg.MaxBodyBytes)),
		row("pdf limit", fmt.Sprintf("%d bytes", cfg.MaxPDFBytes)),
		row("office limit", fmt.Sprintf("%d bytes", cfg.MaxOfficeBytes)),
		row("image limit", fmt.Sprintf("%d bytes", cfg.MaxImageBytes)),
		row("log level", cfg.LogLevel),
		row("log format", cfg.LogFormat),
		// Session mode determines whether the SDK validates Mcp-Session-Id
		// (stateful) or treats every request as a fresh temporary session
		// (stateless).  Set via MCP_STATELESS.
		row("session mode", sessionModeLabel(cfg.Stateless)),
	)
	// Janitor tunables are meaningless in stateless mode — only show them
	// when they actually apply, to avoid suggesting they have an effect
	// the server isn't going to give them.
	if !cfg.Stateless {
		rows = append(rows,
			row("session max age", cfg.SessionMaxAge.String()),
			row("janitor interval", cfg.SessionJanitorInterval.String()),
		)
	}
	// Fetch SSRF policy. The default is public-only; show that explicitly so
	// an operator can confirm at a glance that the fetch tool cannot reach
	// internal targets. When widened via FETCH_ALLOWED_HOSTS /
	// FETCH_ALLOWED_CIDRS, list exactly what was allowed — the raw operator
	// input (order and text preserved), so the banner matches what they set.
	if len(cfg.FetchAllowedHosts) == 0 && len(cfg.FetchAllowedCIDRs) == 0 {
		rows = append(rows, row("fetch policy", "public only"))
	} else {
		rows = append(rows, row("fetch policy", "widened (internal targets allowed)"))
		if len(cfg.FetchAllowedHosts) > 0 {
			rows = append(rows, row("allowed hosts", strings.Join(cfg.FetchAllowedHosts, ", ")))
		}
		if len(cfg.FetchAllowedCIDRs) > 0 {
			rows = append(rows, row("allowed cidrs", strings.Join(cfg.FetchAllowedCIDRs, ", ")))
		}
	}
	rows = append(rows,
		// Token count and identity count: tokens >= identities, because an
		// identity can have multiple tokens during rotation.  Showing both
		// lets an operator sanity-check their config — "I expected 3
		// identities and 4 tokens during the rollover, banner says exactly
		// that, good."
		row("auth tokens", fmt.Sprintf("%d configured (%d identities)",
			len(cfg.AuthTokens), countIdentities(cfg.AuthTokens))),
		// Rate limit: shown unconditionally so it's obvious whether the
		// throttle is engaged.  "disabled" appears when RPS == 0.
		row("rate limit", server.rateLimiter.describe()),
		// Fingerprint of the per-process fence signing key. Rotates each
		// restart; full key material is never logged.
		row("fence key", fenceKeyFingerprint(server.fencePublicKey)),
	)

	maxLen := len(title)
	for _, r := range rows {
		if len(r) > maxLen {
			maxLen = len(r)
		}
	}
	sep := strings.Repeat("#", maxLen)

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(sep + "\n")
	sb.WriteString("\n")
	sb.WriteString(title + "\n")
	sb.WriteString("\n")
	sb.WriteString(sep + "\n")
	sb.WriteString("\n")
	for _, r := range rows {
		sb.WriteString(r + "\n")
	}
	sb.WriteString("\n")
	sb.WriteString(sep + "\n")
	sb.WriteString("\n")

	_, _ = fmt.Fprint(os.Stderr, sb.String())
}

// redactSecret returns "[set]" when s is non-empty and "[not set]" otherwise,
// so secret values are never written to logs.
func redactSecret(s string) string {
	if s != "" {
		return "[set]"
	}
	return "[not set]"
}

// sessionModeLabel renders the cfg.Stateless bool as the human-readable
// banner string.  Keeps the banner row construction tidy.
func sessionModeLabel(stateless bool) string {
	if stateless {
		return "stateless"
	}
	return "stateful"
}
