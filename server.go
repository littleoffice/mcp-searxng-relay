package main

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── Server ────────────────────────────────────────────────────────────────────
//
// Server holds the application backend: HTTP clients, the URL cache, metrics,
// and a reference to the SDK *mcp.Server that owns the JSON-RPC plumbing.
//
// All MCP protocol handling — initialize, tools/list, tools/call, session
// tracking, SSE streaming — is delegated to github.com/modelcontextprotocol/go-sdk.
// We only register tool handlers and wire transports.

type Server struct {
	config      Config
	client      *http.Client // SearXNG requests only
	fetchClient *http.Client // URL fetching — SSRF-safe dialer + redirect check
	cache       *lru.Cache[string, cacheEntry]
	cacheTTL    time.Duration
	metrics     Metrics // in-process counters

	// mcpServer owns the MCP protocol state (tools, sessions, JSON-RPC).
	mcpServer *mcp.Server

	// Fence signing keypair — generated fresh at startup. See fence.go.
	// fencePublicKey is exposed at /fence/public-key in HTTP mode and via
	// the startup banner fingerprint. fenceSigningKey is never logged.
	fenceSigningKey ed25519.PrivateKey
	fencePublicKey  ed25519.PublicKey

	// rateLimiter enforces per-caller request throttling on the HTTP
	// transport.  Nil when the feature is disabled (RPS == 0).  See
	// rate_limit.go for the algorithm; the limiter is allocated in
	// NewServer so tests that construct a Server directly can leave
	// it nil and exercise the no-op fast path.
	rateLimiter *rateLimiter

	// history holds the per-caller fetch history that backs
	// searxng_session_sources.  See history.go for the storage rationale;
	// historyMu guards only the get-or-create, not the ring behind the
	// pointer (fetchHistory has its own lock for that).
	//
	// Nil when a Server is constructed directly in tests, in which case
	// recording is a no-op and the tool returns an empty list.
	history   *lru.Cache[string, *fetchHistory]
	historyMu sync.Mutex

	// health probe cache — avoids hitting SearXNG on every /health request
	healthMu      sync.Mutex
	healthOK      bool
	healthChecked time.Time

	// Session tracking is populated by handleInitialized (only registered
	// in stateful mode) and consumed by runSessionJanitor.  In stateless
	// mode both stay zero-valued and the maps are never written.
	//
	// We track sessions ourselves rather than relying on the SDK's session
	// set because the SDK doesn't store identity-or-creation-time
	// metadata, and that's exactly what audit correlation needs.
	sessionsMu sync.Mutex
	sessions   map[string]*sessionInfo
}

func NewServer(cfg Config) *Server {
	// searchTransport talks only to the configured SearXNG URL; no special
	// SSRF protection needed since the destination is operator-controlled.
	searchTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// fetchTransport uses safeDialContext (defined in ssrf.go) so that the
	// private-IP check happens at TCP-dial time, closing the DNS-rebinding
	// window.  CheckRedirect re-validates each hop for the same reason.
	//
	// Proxy is acl.proxyFor, NOT http.ProxyFromEnvironment as on
	// searchTransport.  Reasoning: when a proxy is configured, Go's
	// http.Transport calls DialContext with the *proxy's* address rather than
	// the target host.  safeDialContext would then validate the proxy
	// (typically a public address — passes) and the proxy itself would route
	// to wherever it pleases, including internal/loopback addresses.  Reading
	// the ambient HTTP_PROXY/HTTPS_PROXY here would therefore let a variable
	// set for some unrelated reason silently defeat the SSRF protection this
	// transport exists to provide.
	//
	// proxyFor instead applies the operator's explicit FETCH_PROXY only where
	// they have already accepted the trade-off — allow-listed hosts, which
	// skip the per-IP check regardless — or, under the separate and
	// deliberately louder FETCH_PROXY_ALL, everywhere, for networks that have
	// no direct egress and where the honest description is that enforcement
	// has moved to the proxy.  See the "Egress proxy" section in ssrf.go.
	// The fetch ACL widens the default public-only SSRF policy with any
	// operator-configured allowed hosts/CIDRs. It is compiled and validated
	// in main(); a Server built directly in tests may leave it nil, in which
	// case we fall back to an empty ACL == the original strict behaviour.
	acl := cfg.FetchACL
	if acl == nil {
		acl = emptyFetchACL()
	}

	fetchTransport := &http.Transport{
		Proxy:               acl.proxyFor,
		DialContext:         acl.safeDialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	cache, err := lru.New[string, cacheEntry](cfg.CacheMaxEntries)
	if err != nil {
		// Only fails when size <= 0, which configFromEnv prevents.
		panic("failed to initialise LRU cache: " + err.Error())
	}

	// Operator-supplied key when one was configured and validated in main(),
	// a fresh per-process keypair otherwise. A Server built directly in tests
	// passes a zero Config, so cfg.FenceKey is nil there and the ephemeral
	// path is taken exactly as before.
	pub, priv := resolveFenceKeypair(cfg.FenceKey)

	s := &Server{
		config: cfg,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: searchTransport,
		},
		fetchClient: &http.Client{
			Timeout:       30 * time.Second,
			Transport:     fetchTransport,
			CheckRedirect: acl.safeCheckRedirect,
		},
		cache:           cache,
		cacheTTL:        cfg.CacheTTL,
		fenceSigningKey: priv,
		fencePublicKey:  pub,
		rateLimiter:     newRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst, cfg.RateLimitExempt),
		history:         newFetchHistoryCache(),
		sessions:        make(map[string]*sessionInfo),
	}
	s.mcpServer = s.buildMCPServer()
	return s
}

// buildMCPServer creates the SDK server and registers our two tools.
//
// We use the generic mcp.AddTool helper so the SDK can infer JSON Schemas
// from the input struct's fields and `jsonschema:"..."` struct tags. Output
// types are 'any' because our tools return free-form Content blocks (text or
// image), not structured records — this tells the SDK to omit an output
// schema.
//
// InitializedHandler is registered only in stateful mode.  In stateless
// mode the SDK fakes a per-request session with default init params and
// no real handshake occurs, so the handler would either never fire or
// fire on every request — neither is useful for audit.
func (s *Server) buildMCPServer() *mcp.Server {
	var serverOpts *mcp.ServerOptions
	if !s.config.Stateless {
		serverOpts = &mcp.ServerOptions{
			InitializedHandler: s.handleInitialized,
		}
	}
	server := mcp.NewServer(
		&mcp.Implementation{Name: projectName, Version: ServerVersion},
		serverOpts,
	)

	mcp.AddTool(server, &mcp.Tool{
		Name: "searxng_web_search",
		Description: "Execute web searches using a SearXNG instance. Returns titles, " +
			"URLs, and snippets, with engine attribution per result. To re-query " +
			"a specific backend, pass its name (as seen in a result's engine " +
			"field) via the engines parameter, e.g. engines='wikipedia,github'.",
	}, s.toolSearch)

	mcp.AddTool(server, &mcp.Tool{
		Name: "searxng_read_url",
		Description: "Fetch a URL and return its content as structured markdown. " +
			"If you have multiple URL candidates and need to pick a subset to read, " +
			"call searxng_url_metadata first for each — it returns title/author/date " +
			"for ~10x less tokens. Use this tool when you've committed to reading " +
			"specific URLs in full. Handles HTML and PDF including large multi-" +
			"hundred-page documents. Non-UTF-8 encodings are detected and converted " +
			"automatically. Image URLs (jpeg/png/gif/webp) are returned as image " +
			"content blocks for vision models. PDF text is delimited by " +
			"'--- [PDF page N of M] ---' marker lines, so you can locate and " +
			"cite specific pages. Long documents are paginated: a " +
			"response ending in a truncation notice tells you the total size and " +
			"the exact start_index to pass on the next call to continue reading. " +
			"Follow-up pages are served from cache, so paging through a document " +
			"costs one upstream fetch. Results are cached; use force_refresh " +
			"to bypass the cache.",
	}, s.toolReadURL)

	mcp.AddTool(server, &mcp.Tool{
		Name: "searxng_url_metadata",
		Description: "When deciding which of several URLs to read in full, call " +
			"this tool first for each candidate to get title, author, publish date, " +
			"language, site name, description, image, categories, and tags as JSON. " +
			"For PDFs it also returns page_count, so you can gauge document size " +
			"before committing to a full read. " +
			"It is ~10x cheaper in tokens than searxng_read_url. After reviewing " +
			"metadata, call searxng_read_url only on the URLs you've decided are " +
			"worth full content. Also use this tool standalone for citation building " +
			"or when you need to verify a publish date without reading the article. " +
			"Results are cached and shared with searxng_read_url — a metadata fetch " +
			"followed by a content fetch needs only one upstream HTTP request.",
	}, s.toolURLMetadata)

	mcp.AddTool(server, &mcp.Tool{
		Name: "searxng_session_sources",
		Description: "List the URLs this relay has actually fetched for you, " +
			"byte-exact, newest first. Call this before writing any answer that " +
			"contains URLs, and copy the URLs from its output rather than from " +
			"memory — a URL recalled from earlier in a long conversation is " +
			"frequently wrong in ways that are not visible until someone clicks " +
			"it. Each entry records how much was read (full / partial / metadata " +
			"only) and whether the fetch succeeded, so you can tell which sources " +
			"you are entitled to cite as read. A URL that does not appear here " +
			"was not fetched by this relay. Pass since_seq to see only what has " +
			"been fetched since a previous call. History is per caller and " +
			"in-memory: it covers the current session and does not survive a " +
			"server restart.",
	}, s.toolSessionSources)

	return server
}

// sessionIDOf returns the session ID for a CallToolRequest, or "" when
// either the request or its session is nil (defensive: stateless mode
// may pass an ephemeral session, and unit tests may construct a request
// without one).  Tool handlers use this for audit log lines.
func sessionIDOf(req *mcp.CallToolRequest) string {
	if req == nil || req.Session == nil {
		return ""
	}
	return req.Session.ID()
}

// handleInitialized is the ServerOptions.InitializedHandler hook fired when
// a client finishes the MCP initialize handshake (it sends the
// notifications/initialized notification).  We use it to record session
// metadata for two consumers:
//
//   - audit logs: a single info-level line at handshake time, including
//     the identity matched by requireAuth and the session ID the SDK
//     assigned. Subsequent tool-call log lines share that session_id, so
//     forensics can join "what was done" (tool calls) to "by whom"
//     (initialize line) via the common session_id.
//
//   - idle-session janitor: it walks s.sessions looking for entries older
//     than the maxAge constant in runSessionJanitor and closes them via
//     the SDK.
//
// Identity is read from the context the SDK passes through from the
// originating HTTP request — requireAuth attached it there before the
// SDK handler ran.  If the context carries no identity (stdio mode, or a
// future bypass we haven't anticipated), we still record the session but
// with an empty identity.
//
// Client name/version from InitializeRequest.Params would be a useful
// addition — see the README's known-limitations section. Not done in this
// pass because the exact field path in the v1.4.1 SDK was not verified
// against a running build; adding it is a one-line change once confirmed.
func (s *Server) handleInitialized(ctx context.Context, req *mcp.InitializedRequest) {
	if req == nil || req.Session == nil {
		return
	}
	sid := req.Session.ID()
	identity := identityFromContext(ctx)

	s.sessionsMu.Lock()
	s.sessions[sid] = &sessionInfo{
		Identity:  identity,
		CreatedAt: time.Now(),
	}
	s.sessionsMu.Unlock()

	slog.Info("session initialized",
		"session_id", sid,
		"identity", identity)
}

// runSessionJanitor wakes every cfg.SessionJanitorInterval, walks the SDK's
// live session set, and:
//
//   - removes our tracking entry for any session that's no longer live
//     (handles cleanly-closed sessions and out-of-band SDK closures);
//   - closes any session that's been alive longer than cfg.SessionMaxAge,
//     plus removes its tracking entry.
//
// Both values come from configFromEnv (MCP_SESSION_MAX_AGE and
// MCP_SESSION_JANITOR_INTERVAL) with safe defaults that should fit most
// deployments — see the README's "Tuning the session janitor" section
// for when to deviate.  We read them once at goroutine start; a config
// reload would require restarting the process.
//
// Only run in stateful mode (runHTTP gates the goroutine launch).  In
// stateless mode there are no sessions to clean up.
func (s *Server) runSessionJanitor(ctx context.Context) {
	maxAge := s.config.SessionMaxAge
	interval := s.config.SessionJanitorInterval

	slog.Info("session janitor started",
		"interval", interval,
		"max_age", maxAge)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reapStaleSessions(maxAge)
		}
	}
}

// reapStaleSessions performs one janitor pass.  Split out from
// runSessionJanitor so a test can drive it deterministically without
// depending on time.Ticker.
func (s *Server) reapStaleSessions(maxAge time.Duration) {
	// Snapshot live sessions from the SDK into a map for O(1) lookup,
	// and collect the ones we may need to close.
	live := make(map[string]*mcp.ServerSession)
	for sess := range s.mcpServer.Sessions() {
		live[sess.ID()] = sess
	}

	now := time.Now()
	var toClose []*mcp.ServerSession
	var closed, stale int

	s.sessionsMu.Lock()
	for sid, info := range s.sessions {
		sess, alive := live[sid]
		if !alive {
			// Session is gone from the SDK's view (already closed by
			// the client's DELETE or by some SDK-internal path).  Drop
			// our tracking entry.
			delete(s.sessions, sid)
			stale++
			continue
		}
		if now.Sub(info.CreatedAt) > maxAge {
			toClose = append(toClose, sess)
			delete(s.sessions, sid)
			closed++
		}
	}
	s.sessionsMu.Unlock()

	// Close outside the lock to avoid holding it during whatever SDK
	// teardown work happens in Close().
	for _, sess := range toClose {
		slog.Info("janitor closing idle session", "session_id", sess.ID())
		_ = sess.Close()
	}

	if closed > 0 || stale > 0 {
		slog.Debug("janitor pass", "closed", closed, "stale_entries_dropped", stale)
	}
}

// newSearxRequest builds an outbound HTTP request to SearXNG with auth and
// user-agent applied.  Not used for arbitrary URL fetches.
func (s *Server) newSearxRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.config.UserAgent)
	if s.config.AuthUsername != "" || s.config.AuthPassword != "" {
		req.SetBasicAuth(s.config.AuthUsername, s.config.AuthPassword)
	}
	return req, nil
}

// sessionCount returns the number of currently active MCP sessions.
//
// The SDK does not expose a counter directly; we iterate the live session
// set. This is O(n) but called rarely (on /metrics scrape and on each
// initialize for the soft session cap), and n is bounded by maxSessions.
//
// Returns 0 when mcpServer is nil, which is the shape a Server constructed
// directly in a test takes. Every other optional collaborator on Server is
// already nil-safe for exactly that reason — history, rateLimiter and
// FetchACL all say so in their own comments — and this one silently was not,
// so calling ServeMetrics on such a Server panicked rather than reporting
// zero sessions.
func (s *Server) sessionCount() int {
	if s.mcpServer == nil {
		return 0
	}
	n := 0
	for range s.mcpServer.Sessions() {
		n++
	}
	return n
}
