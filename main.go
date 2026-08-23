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

	"github.com/andybalholm/cascadia"
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

	// Optional /health bearer token (MCP_HEALTH_TOKEN) — a separate secret
	// from the MCP tokens above. Parsed here, before NewServer copies cfg,
	// so the server's config carries it (requireHealthAuth reads
	// server.config, and so does the startup banner). Unset leaves /health
	// open, matching historical behaviour; a too-short value fails startup
	// with the same fail-loud stance as the MCP tokens.
	healthToken, err := parseHealthToken()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	cfg.HealthToken = healthToken

	// /metrics bearer token (MCP_METRICS_TOKEN) — again a secret of its own,
	// and unlike MCP_HEALTH_TOKEN it is required rather than optional.
	// /metrics serves mcp_fetches_by_domain_total, which names the destination
	// hosts this relay has fetched across ALL callers; serving that to the
	// shared MCP token table would make every tenant's fetch targets readable
	// by every other tenant. Unset closes the endpoint (401) rather than
	// falling back — see requireMetricsAuth. A too-short value fails startup
	// with the same fail-loud stance as the MCP tokens.
	metricsToken, err := parseMetricsToken()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	cfg.MetricsToken = metricsToken

	// Compile the fetch allow-list (FETCH_ALLOWED_HOSTS / FETCH_ALLOWED_CIDRS).
	// A malformed CIDR fails startup with a clear message — the same
	// fail-loud stance as the auth-token parser, since this is a security
	// control and a typo must not silently widen or narrow it.
	acl, err := newFetchACL(cfg.FetchAllowedHosts, cfg.FetchAllowedCIDRs)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	// Install the egress proxy (FETCH_PROXY / FETCH_PROXY_ALL). Same
	// fail-loud stance: a malformed proxy URL, an unsupported scheme, or a
	// scope set with no proxy to route through stops the server. Degrading
	// silently to "no proxy" would be worse than not starting — in a network
	// with no direct egress every fetch would hang until its timeout.
	if err := acl.setProxy(cfg.FetchProxy, cfg.FetchProxyAll); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	cfg.FetchACL = acl

	// Validate the pre-extraction prune selector.  go-trafilatura parses it
	// with cascadia and silently skips pruning when the parse fails
	// (core.go:127), so a typo would quietly restore the content-selection
	// bug this setting exists to prevent — with correct-looking output and
	// no error anywhere.  Fail loudly at startup instead, matching the
	// stance taken for auth tokens and the fetch allow-list above.
	if cfg.PruneSelector != "" {
		if _, err := cascadia.ParseGroup(cfg.PruneSelector); err != nil {
			_, _ = fmt.Fprintf(os.Stderr,
				"Error: PRUNE_SELECTOR is not a valid CSS selector: %v\n", err)
			os.Exit(1)
		}
	}

	// Leave an audit line when the default public-only SSRF policy has been
	// widened, so it is obvious from the logs that the fetch tool can reach
	// internal resources and exactly which ones.
	if !acl.isEmpty() {
		slog.Warn("fetch SSRF policy widened by operator config",
			"allowed_hosts", cfg.FetchAllowedHosts,
			"allowed_cidrs", cfg.FetchAllowedCIDRs,
			"hint", "the fetch tool can now reach these internal hosts/ranges; keep the lists tight")
		// Per-range detail. A prefix length does not convey its own size —
		// "10.0.0.0/8" is eleven characters that grant reach to 16.7 million
		// addresses — so the count and any sensitive address the range sweeps
		// in are stated explicitly rather than left to be inferred.
		acl.logCIDRBlastRadius()
	}

	// A proxy scoped to allow-listed hosts changes reach but not enforcement,
	// so it logs at info. FETCH_PROXY_ALL hands the per-IP policy to the
	// proxy outright and gets the same warn-level treatment as a widened
	// allow-list: an operator reading the logs should never have to infer
	// that assertPublicIP has stopped participating.
	if acl.proxyConfigured() {
		if cfg.FetchProxyAll {
			slog.Warn("fetch egress proxy applies to ALL fetches",
				"proxy", acl.describeProxy(),
				"hint", "the relay no longer resolves destinations itself, so the public-IP check and FETCH_ALLOWED_CIDRS no longer apply; the proxy is now the enforcement point")
		} else {
			slog.Info("fetch egress proxy configured for allow-listed hosts",
				"proxy", acl.describeProxy())
		}
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

	// Resolve the fence signing key (FENCE_SIGNING_KEY / FENCE_SIGNING_KEY_FILE).
	// Unset — the default — leaves the per-process ephemeral key untouched.
	// Same fail-loud stance as the controls above: an operator who configured
	// a key did so because something downstream pins its fingerprint, and
	// starting with a silently different key would make every fence fail
	// verification at that verifier with no obvious cause.
	fenceKey, fenceKeySource, err := loadFenceSigningKey(cfg.FenceSigningKey, cfg.FenceSigningKeyFile)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	cfg.FenceKey = fenceKey
	cfg.FenceKeySource = fenceKeySource

	server := NewServer(cfg)

	// Leave an audit line when the signing key outlives the process. This
	// reverses a deliberate default, and it changes the blast radius of a
	// key leak from one process lifetime to "until the operator rotates" —
	// so it belongs in the logs, not merely inferable from the environment.
	// Logged after NewServer so the fingerprint comes from the public key the
	// server will actually publish at /fence/public-key, not from a
	// separately derived copy that could drift from it.
	if fenceKey != nil {
		slog.Warn("fence signing key is persistent, not per-process",
			"source", fenceKeySource,
			"fingerprint", fenceKeyFingerprint(server.fencePublicKey),
			"hint", "fences stay verifiable across restarts; rotate this key on the same cadence as your other signing material")
	}

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
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+"/health", nil)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		os.Exit(1)
	}
	// If MCP_HEALTH_TOKEN is set the endpoint requires it. The probe reads
	// the same env var the server reads, so a single entry covers both the
	// server and its own Docker HEALTHCHECK probe with no extra wiring.
	if healthToken := strings.TrimSpace(os.Getenv("MCP_HEALTH_TOKEN")); healthToken != "" {
		req.Header.Set("Authorization", "Bearer "+healthToken)
	}
	resp, err := client.Do(req)
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

	// /metrics has no credential, so it will 401 every scrape. Say so once at
	// startup: the alternative is an operator debugging a silent monitoring
	// gap from the scraper's side, where the 401 looks like a scrape-config
	// bug rather than a deliberate default on this end.
	if len(cfg.MetricsToken) == 0 {
		slog.Warn("/metrics is closed: MCP_METRICS_TOKEN is not set",
			"hint", "generate one with `openssl rand -hex 32`; it is deliberately NOT the MCP auth token, because /metrics discloses the destination hosts fetched for every caller")
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
	// MCP root: per-caller rate limit → bearer auth → conversation ID → soft
	// session cap → SDK handler.
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
	//
	// trackClientSession sits after auth and is a no-op outside stateless
	// mode: it attaches the client-asserted conversation ID that the SDK
	// stopped reading in go-sdk v1.7.0, so audit lines and the per-caller
	// source ledger can still tell two conversations under one token apart.
	mux.Handle("/", server.rateLimit(server.requireAuth(server.trackClientSession(server.limitSessions(mcpHandler)))))
	// /health is open by default for load balancers, and intentionally NOT
	// rate-limited so a polling LB never gets 429. requireHealthAuth gates it
	// behind MCP_HEALTH_TOKEN when that is set (a no-op wrapper otherwise);
	// note that turning it on means every prober — external LBs and
	// Kubernetes httpGet probes included — must then send the token.
	mux.Handle("/health", server.requireHealthAuth(http.HandlerFunc(server.handleHealth)))
	// /fence/public-key is intentionally unauthenticated — public keys are public.
	mux.HandleFunc("/fence/public-key", server.handleFencePublicKey)
	// /metrics is behind MCP_METRICS_TOKEN when one is set, and behind the
	// MCP token table otherwise (see requireMetricsAuth for why a dedicated
	// secret is worth setting).  We deliberately do NOT rate-limit it:
	// monitoring scrapers poll on a schedule that's already low-rate, and a
	// 429 from /metrics would produce gaps in Prometheus that look identical
	// to outages.  An abusive scraper is better contained by withholding the
	// token.
	mux.Handle("/metrics", server.requireMetricsAuth(http.HandlerFunc(server.ServeMetrics)))

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
	// Engine-token count, never the values: the banner goes to stderr and
	// from there into whatever collects container logs.  The count is what an
	// operator needs to confirm the Secret was mounted and parsed as expected
	// ("I configured two, it says two"), and it is enough to catch the common
	// failure of an empty or whitespace-only value being silently accepted.
	if n := len(cfg.SearxngTokens); n > 0 {
		rows = append(rows, row("searxng tokens", fmt.Sprintf("%d configured", n)))
	}
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
		row("extract limit", fmt.Sprintf("%d chars", cfg.MaxExtractedChars)),
		row("source history", fmt.Sprintf("%d per caller", cfg.HistoryEntries)),
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
	// Egress proxy. Shown only when configured, so the banner of an
	// unproxied deployment is unchanged. describeProxy redacts any password
	// in the proxy URL's userinfo and names the scope explicitly.
	if cfg.FetchACL != nil && cfg.FetchACL.proxyConfigured() {
		rows = append(rows, row("fetch proxy", cfg.FetchACL.describeProxy()))
	}
	rows = append(rows,
		// Token count and identity count: tokens >= identities, because an
		// identity can have multiple tokens during rotation.  Showing both
		// lets an operator sanity-check their config — "I expected 3
		// identities and 4 tokens during the rollover, banner says exactly
		// that, good."
		row("auth tokens", fmt.Sprintf("%d configured (%d identities)",
			len(cfg.AuthTokens), countIdentities(cfg.AuthTokens))),
		// Whether the /health probe requires MCP_HEALTH_TOKEN. Shown only in
		// HTTP mode — stdio has no /health endpoint for it to apply to.
		row("health auth", healthAuthLabel(mode, len(cfg.HealthToken) > 0)),
		// Whether /metrics has a credential at all. Worth showing
		// unconditionally: without one the endpoint is closed, and an
		// operator whose dashboards have gone blank should find the reason
		// here rather than in the scraper's logs.
		row("metrics auth", metricsAuthLabel(mode, len(cfg.MetricsToken) > 0)),
		// Rate limit: shown unconditionally so it's obvious whether the
		// throttle is engaged.  "disabled" appears when RPS == 0.
		row("rate limit", server.rateLimiter.describe()),
		// Whether hyperlink targets from fetched HTML are surfaced to the
		// agent.  Shown unconditionally: it changes what the model sees,
		// so it belongs in the same at-a-glance view as the fetch policy.
		row("link extraction", enabledLabel(cfg.ExtractLinks)),
		// Pre-extraction pruning changes which subtree is treated as the
		// article, so an operator debugging odd extraction output needs to
		// see the active selector, not just whether it is on.
		row("prune selector", prunePolicyLabel(cfg.PruneSelector)),
		// Fingerprint of the fence signing key, plus whether it survives a
		// restart. An operator wiring up a verifying gateway needs the
		// persistence state at a glance, because it decides whether the
		// fingerprint they pin is stable or has to be re-read after every
		// deploy. Full key material is never logged.
		row("fence key", fenceKeyLabel(server.fencePublicKey, cfg.FenceKeySource)),
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

// prunePolicyLabel renders the prune selector for the banner, making the
// disabled state explicit rather than showing a blank value.
func prunePolicyLabel(sel string) string {
	if strings.TrimSpace(sel) == "" {
		return "disabled (no pre-extraction pruning)"
	}
	return sel
}

// enabledLabel renders a feature toggle as a banner-friendly word.
func enabledLabel(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// healthAuthLabel renders the /health authentication state for the banner.
// It is mode-aware: stdio has no /health endpoint, so the token cannot apply
// there and saying "disabled" would be misleading. In HTTP mode the disabled
// string names the env var so an operator sees at a glance how to turn it on.
func healthAuthLabel(mode string, enabled bool) string {
	if mode != "streamable-http" {
		return "n/a (stdio has no /health endpoint)"
	}
	if enabled {
		return "enabled (MCP_HEALTH_TOKEN set)"
	}
	return "disabled (/health open — set MCP_HEALTH_TOKEN to require a token)"
}

// metricsAuthLabel renders the /metrics authentication state for the banner.
// Mode-aware for the same reason healthAuthLabel is: stdio has no /metrics
// endpoint. The unset string says the endpoint is CLOSED rather than
// "disabled", because the distinction an operator needs is "nothing can
// scrape this" and not "a feature is off".
func metricsAuthLabel(mode string, configured bool) string {
	if mode != "streamable-http" {
		return "n/a (stdio has no /metrics endpoint)"
	}
	if configured {
		return "enabled (MCP_METRICS_TOKEN set)"
	}
	return "CLOSED (/metrics returns 401 — set MCP_METRICS_TOKEN to enable scraping)"
}

// sessionModeLabel renders the cfg.Stateless bool as the human-readable
// banner string.  Keeps the banner row construction tidy.
func sessionModeLabel(stateless bool) string {
	if stateless {
		return "stateless"
	}
	return "stateful"
}
