package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// ── Config ────────────────────────────────────────────────────────────────────

// tokenDigest is the SHA-256 of the full Authorization header value
// ("Bearer "+token).  We never store the raw token; the digest is what
// requireAuth looks up.  Using a fixed-size key means the lookup itself
// can't leak token bytes via timing (the input has already been hashed).
type tokenDigest [32]byte

type Config struct {
	SearxngURL    string
	AuthUsername  string
	AuthPassword  string
	SearxngTokens []string // SEARXNG_TOKENS: private-engine tokens, sent as ?tokens= on every search
	UserAgent     string
	LogLevel      string
	LogFormat     string
	AuthTokens    map[tokenDigest]string // digest → identity, populated by parseAuthTokens
	// HealthToken gates the /health probe. It is a SEPARATE secret from the
	// MCP bearer tokens in AuthTokens — the health probe and the MCP endpoint
	// are different trust domains and must not share a credential. Populated
	// by parseHealthToken from MCP_HEALTH_TOKEN; nil/empty (the default)
	// leaves /health open, which is the historical behaviour. A set is used
	// rather than a digest→identity map because the health token carries no
	// identity: it is a single shared secret, not a per-caller credential.
	HealthToken map[tokenDigest]struct{}
	// MetricsToken gates the /metrics endpoint, and is a SEPARATE secret from
	// the MCP bearer tokens for the same reason HealthToken is. /metrics
	// exposes mcp_fetches_by_domain_total, i.e. the set of hostnames every
	// *other* tenant has been fetching. On a relay with FETCH_ALLOWED_HOSTS
	// set those are internal hostnames, so serving it to a per-tenant
	// credential discloses the internal estate to every tenant that holds one.
	//
	// Populated by parseMetricsToken from MCP_METRICS_TOKEN. Unlike
	// HealthToken, this one is REQUIRED: nil/empty closes /metrics to
	// everyone (401) rather than falling back to the MCP token table. See
	// requireMetricsAuth for why the boundary is not made optional, and note
	// that this differs deliberately from HealthToken, whose unset state
	// leaves /health open.
	MetricsToken           map[tokenDigest]struct{}
	Stateless              bool          // MCP_STATELESS=true → SDK skips session tracking
	SessionMaxAge          time.Duration // MCP_SESSION_MAX_AGE: idle-session reap age (stateful only)
	SessionJanitorInterval time.Duration // MCP_SESSION_JANITOR_INTERVAL: how often the janitor wakes
	CacheTTL               time.Duration
	CacheMaxEntries        int
	HistoryEntries         int // MCP_HISTORY_ENTRIES: sources retained per caller
	MaxBodyBytes           int64
	MaxPDFBytes            int64
	MaxOfficeBytes         int64
	MaxImageBytes          int64
	MaxExtractedChars      int      // MAX_EXTRACTED_CHARS: cap on extracted text cached per URL
	RateLimitRPS           float64  // MCP_RATE_LIMIT_RPS: per-caller sustained rate (requests/sec); 0 disables
	RateLimitBurst         int      // MCP_RATE_LIMIT_BURST: token-bucket capacity
	RateLimitExempt        []string // MCP_RATE_LIMIT_EXEMPT: identities bypassed entirely (e.g. monitoring)

	// Fetch allow-list (opt-in SSRF widening). Both empty by default, which
	// keeps the fetch tool restricted to public IPs. Raw values are read here;
	// FetchACL is the compiled, validated form populated in main() (see
	// newFetchACL). Storing the raw lists too keeps the startup banner and any
	// future /config introspection honest about what was configured.
	FetchAllowedHosts []string  // FETCH_ALLOWED_HOSTS: host:port entries exempt from the public-IP check
	FetchAllowedCIDRs []string  // FETCH_ALLOWED_CIDRS: range/prefix:port entries treated as reachable
	FetchACL          *fetchACL // compiled form; nil until main() validates the two lists

	// Egress proxy for the fetch tool. Deliberately separate from the
	// ambient HTTP_PROXY/HTTPS_PROXY that searchTransport honours — see the
	// "Egress proxy" section in ssrf.go for why. Empty/false by default.
	FetchProxy    string // FETCH_PROXY: proxy URL (http, https, socks5, socks5h)
	FetchProxyAll bool   // FETCH_PROXY_ALL: route every fetch through it, not just allow-listed hosts

	// ExtractLinks controls whether hyperlink targets from fetched HTML
	// reach the model. EXTRACT_LINKS=false restores the previous behaviour
	// (anchor text only, targets dropped) for deployments that would rather
	// not put page-controlled URLs in front of an agent at all. Affects HTML
	// only: Office documents carry their own links through the office_oxide
	// converter regardless of this switch.
	ExtractLinks bool // EXTRACT_LINKS: default true

	// ExtractSandbox runs PDF/Office extraction (the native pdf_oxide /
	// office_oxide cgo path) in a locked-down subprocess so a parser bug reached
	// via a malicious document is contained away from the server's secrets and
	// network. Default true; EXTRACT_SANDBOX=false falls back to in-process
	// extraction (the historical behaviour) as an escape hatch. See sandbox.go.
	ExtractSandbox bool // EXTRACT_SANDBOX: default true
	// ExtractTimeout is the hard wall-clock deadline for a single sandboxed
	// extraction, after which the child is SIGKILLed and the fetch returns a
	// contained error. Ignored when ExtractSandbox is false.
	ExtractTimeout time.Duration // EXTRACT_TIMEOUT: default 60s

	// PruneSelector is a CSS selector whose matches are removed from the
	// document BEFORE trafilatura chooses which subtree is the article.
	// Without it, sites that wrap boilerplate in a container the extractor
	// finds attractive can have that container selected instead of the
	// article — silently, with no error and plausible-looking text. See the
	// README for the default and how it was derived.
	//
	// PRUNE_SELECTOR overrides it; setting it to the empty string disables
	// pruning entirely (unset and empty are distinguished via os.LookupEnv).
	PruneSelector string // PRUNE_SELECTOR

	// Fence signing key persistence (opt-in). Raw values are read here; the
	// parsed key is populated in main() via loadFenceSigningKey, following
	// the same "read raw, validate in main" split used for FetchACL above,
	// so a malformed key fails startup with a clear message rather than
	// silently degrading to an ephemeral key that a downstream verifier
	// would then reject every fence from.
	//
	// Both unset — the default — preserves the original behaviour: a fresh
	// keypair generated per process. See fence_key.go for the rationale and
	// the accepted encodings.
	FenceSigningKey     string             // FENCE_SIGNING_KEY: inline key material
	FenceSigningKeyFile string             // FENCE_SIGNING_KEY_FILE: path to a file holding the same
	FenceKey            ed25519.PrivateKey // parsed form; nil until main() validates, and nil means ephemeral
	FenceKeySource      string             // human-readable origin for the banner; empty means ephemeral
}

func configFromEnv() Config {
	c := Config{
		SearxngURL:   strings.TrimRight(os.Getenv("SEARXNG_URL"), "/"),
		AuthUsername: os.Getenv("AUTH_USERNAME"),
		AuthPassword: os.Getenv("AUTH_PASSWORD"),
		UserAgent:    os.Getenv("USER_AGENT"),
		LogLevel:     os.Getenv("LOG_LEVEL"),
		LogFormat:    os.Getenv("LOG_FORMAT"),
	}
	if c.UserAgent == "" {
		c.UserAgent = projectName + "/" + ServerVersion
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.LogFormat == "" {
		c.LogFormat = "text"
	}
	c.CacheTTL = parseDuration(os.Getenv("CACHE_TTL_SECONDS"), 300) * time.Second
	c.CacheMaxEntries = parseInt(os.Getenv("CACHE_MAX_ENTRIES"), 1_000)
	c.MaxBodyBytes = parseInt64(os.Getenv("MAX_BODY_BYTES"), 500_000)
	c.MaxPDFBytes = parseInt64(os.Getenv("MAX_PDF_BYTES"), 50_000_000)
	// MaxOfficeBytes caps the response body for Office documents (DOCX,
	// XLSX, PPTX + legacy DOC, XLS, PPT). Modern OOXML files are ZIP
	// archives whose payload routinely includes embedded images, fonts,
	// and chart data — a deck or workbook can easily push past 50 MB even
	// when its extracted text is modest. The default mirrors PDF.
	c.MaxOfficeBytes = parseInt64(os.Getenv("MAX_OFFICE_BYTES"), 50_000_000)
	// MaxImageBytes is the raw on-disk size limit. The SDK base64-encodes
	// image bytes into the JSON-RPC response, which expands data by ~4/3, so
	// 7.5 MB raw fits inside ~10 MB on the wire. Operators with vision
	// models that handle larger inputs can bump this — just remember the
	// encoded form is what the agent receives.
	c.MaxImageBytes = parseInt64(os.Getenv("MAX_IMAGE_BYTES"), 7_500_000)
	// MaxExtractedChars caps how much *extracted text* is kept (and cached)
	// per URL, as distinct from the Max*Bytes knobs above which cap the raw
	// response body read off the wire.  The per-response window returned to
	// the agent is separately bounded by maxRenderedChars (100k) and paged
	// via the read tool's start_index / max_chars parameters — this cap is
	// what pagination can page *through*.
	//
	// Memory math for operators: worst case the text cache holds
	// CACHE_MAX_ENTRIES × MAX_EXTRACTED_CHARS bytes of content (defaults:
	// 1,000 × 1,000,000 = ~1 GB).  In practice almost no page extracts to
	// anywhere near the cap — the worst case requires 1,000 distinct
	// megabyte-plus documents resident at once.  Deployments on tight
	// memory budgets should lower CACHE_MAX_ENTRIES or this value; raising
	// it lets pagination reach deeper into very large PDFs.
	c.MaxExtractedChars = parseInt(os.Getenv("MAX_EXTRACTED_CHARS"), 1_000_000)
	// HistoryEntries caps how many distinct sources searxng_session_sources
	// retains per caller.  Slots hold sources, not fetches — repeat fetches
	// of a URL already held fold into its entry — so this is a count of
	// things an agent might cite, and 50 covers a research task with room
	// to spare.
	//
	// The binding constraint on raising it is context, not memory.  The list
	// is read into the model's context on every call, and it is called at
	// the point in a conversation where context is scarcest; at roughly
	// 40-80 tokens per entry, 50 sources cost well under a page and 500
	// would cost several.  Memory is the lesser worry: the worst case is
	// MCP_HISTORY_ENTRIES × 1,000 callers × a small record.  Raise it for
	// long-running agents that genuinely visit more sources than the
	// default, and watch mcp_history_evictions_total to find out whether
	// they do.
	c.HistoryEntries = parseInt(os.Getenv("MCP_HISTORY_ENTRIES"), fetchHistoryEntries)
	c.Stateless = parseBool(os.Getenv("MCP_STATELESS"))
	// Link extraction — on by default.  Setting EXTRACT_LINKS=false
	// restores the historical behaviour of dropping hyperlink targets
	// entirely, which is the right call for deployments that treat any
	// page-supplied URL as something an agent should never see.  Note
	// that turning this on also enables trafilatura's own relative →
	// absolute href rewriting, which is gated behind the same option.
	c.ExtractLinks = parseBoolDefault(os.Getenv("EXTRACT_LINKS"), true)
	// Extraction sandbox — on by default. Setting EXTRACT_SANDBOX=false runs the
	// native PDF/Office extractors in-process (the historical behaviour), which
	// removes the per-fetch subprocess cost at the price of the containment the
	// sandbox provides. The timeout bounds a single sandboxed extraction; a
	// malformed value falls back to the default, matching the other knobs.
	c.ExtractSandbox = parseBoolDefault(os.Getenv("EXTRACT_SANDBOX"), true)
	c.ExtractTimeout = parseGoDuration(os.Getenv("EXTRACT_TIMEOUT"), defaultExtractTimeout)
	// Pre-extraction pruning.  The default targets "related"-flavoured
	// containers, which is where news templates habitually park
	// most-popular / you-might-also-like blocks.  It was chosen by
	// measurement rather than taste: on a Register article the extractor
	// selected the most-popular sidebar instead of the story (the h1 never
	// appeared in the output), and this is the narrowest selector that
	// corrected it while leaving a heise article byte-identical.
	//
	// Two clauses that look equally sensible are deliberately absent:
	// "header" and "footer" match <article><header><h1>…, which is
	// ordinary HTML5, and pruning them decapitates articles on sites that
	// use them (observed on heise).  Do not add them back without
	// re-running the h1-survival check across several templates.
	c.PruneSelector = lookupString("PRUNE_SELECTOR", `[class*="related"], [id*="related"]`)
	// Stateful-mode janitor tuning.  Two knobs, two reasons:
	//
	//   - SessionMaxAge is policy: how long a session is allowed to live
	//     before the janitor closes it.  Defaults to 7d, which comfortably
	//     covers AI-workflow patterns (workday idle gaps, overnight runs,
	//     weekend lulls) without leaving zombie sessions around for
	//     unbounded time.  Lower it for tighter audit segmentation or to
	//     match a token rotation cadence; raise it for batch/scheduled
	//     agents that may go idle for days.
	//
	//   - SessionJanitorInterval is mechanism: how often the janitor wakes
	//     to do its sweep.  Defaults to 15m.  Worst-case overshoot past
	//     SessionMaxAge is one interval, which is fine — the cap is
	//     "approximately 7 days", not a hard deadline.  Tighten for
	//     deployments with many short-lived agents where the tracking map
	//     would otherwise stay populated with stale entries between
	//     sweeps.
	//
	// Both accept Go duration syntax ("30m", "12h", "168h" — note that
	// time.ParseDuration does not understand "d" or "w").  Zero or
	// malformed values fall back to defaults.  Stateless mode ignores
	// both: there's no session state to reap.
	c.SessionMaxAge = parseGoDuration(os.Getenv("MCP_SESSION_MAX_AGE"), 7*24*time.Hour)
	c.SessionJanitorInterval = parseGoDuration(os.Getenv("MCP_SESSION_JANITOR_INTERVAL"), 15*time.Minute)
	// Rate limiting — on by default with a conservative ceiling.  5 rps
	// sustained is well above the call rate of a single LLM agent
	// reasoning over a tool, even a chatty one (typical pattern is 1-3
	// tool calls per agent turn with seconds of model think-time between),
	// but low enough to absorb a runaway agent or token-leak attack
	// before the upstream SearXNG instance notices.  Burst 10 lets a
	// well-behaved caller make a flurry of metadata/read pairs without
	// being held up.
	//
	// Set MCP_RATE_LIMIT_RPS=0 to disable.  Set negative or non-numeric
	// values fall back to the default, matching the parse-helper pattern
	// elsewhere in this file — a typo should not silently unlock
	// unbounded traffic.
	c.RateLimitRPS = parseFloat64(os.Getenv("MCP_RATE_LIMIT_RPS"), 5.0)
	// Burst follows RPS by default when not explicitly set: 2x rate
	// rounded up gives a one-second "warm" allowance plus headroom for
	// concurrent tool calls inside a single agent turn.  Operators who
	// want strict pacing set burst == ceil(rate).
	defaultBurst := int(math.Max(1, math.Ceil(c.RateLimitRPS*2)))
	c.RateLimitBurst = parseInt(os.Getenv("MCP_RATE_LIMIT_BURST"), defaultBurst)
	c.RateLimitExempt = parseCSV(os.Getenv("MCP_RATE_LIMIT_EXEMPT"))
	// SearXNG private-engine tokens — comma-separated, forwarded verbatim as
	// the `tokens` search parameter.  An engine carrying a `tokens:` list in
	// settings.yml is invisible and unusable to any caller that does not
	// present one of them, so this is what scopes a relay to a subset of the
	// engines on a shared SearXNG instance.
	//
	// Deliberately process-wide rather than per-identity: the boundary this
	// draws is "this relay may reach these engines", enforced upstream by
	// SearXNG's own validate_token.  Per-caller scoping would put the check
	// in this process, where the `engines` parameter is only one of several
	// ways to select an engine (bang syntax inside the query string is
	// another), and a filter that misses one of them fails open.  One relay
	// per trust boundary keeps the enforcement where it cannot be bypassed.
	c.SearxngTokens = parseCSV(os.Getenv("SEARXNG_TOKENS"))
	// Fetch allow-list — comma-separated. Parsed into raw slices here; the
	// hosts and CIDRs are compiled and validated in main() via newFetchACL so
	// a bad entry fails startup with a clear message instead of being silently
	// dropped. Empty (the default) leaves the strict public-only policy.
	//
	// Both lists require an explicit port: "host:port" and
	// "range/prefix:port". A bare entry is a startup error rather than a
	// shorthand for "every port". See the allowedHosts and allowedCIDRs
	// comments in ssrf.go for why, and note that a default-route prefix
	// (0.0.0.0/0, ::/0) is refused outright — it removes the address policy
	// rather than widening it.
	c.FetchAllowedHosts = parseCSV(os.Getenv("FETCH_ALLOWED_HOSTS"))
	c.FetchAllowedCIDRs = parseCSV(os.Getenv("FETCH_ALLOWED_CIDRS"))
	// Egress proxy — validated in main() via fetchACL.setProxy so a bad URL
	// or a scope set without a proxy fails startup rather than degrading to
	// "no proxy" and timing out on every fetch.
	c.FetchProxy = strings.TrimSpace(os.Getenv("FETCH_PROXY"))
	c.FetchProxyAll = parseBool(os.Getenv("FETCH_PROXY_ALL"))
	// Fence signing key — only the raw strings are read here. Decoding and
	// validation happen in main() via loadFenceSigningKey, which also decides
	// between them (setting both is an error, not a precedence question).
	// Leaving both unset keeps the per-process ephemeral key.
	c.FenceSigningKey = strings.TrimSpace(os.Getenv(fenceKeyEnvVar))
	c.FenceSigningKeyFile = strings.TrimSpace(os.Getenv(fenceKeyFileEnvVar))
	return c
}

// parseBool accepts "1", "true", "yes", "on" (case-insensitive) as true.
// Anything else — including empty — is false.  Conservative on purpose:
// we want a typo in MCP_STATELESS to leave the server in the safer
// (stateful, auditable) default rather than silently flipping modes.
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// lookupString reads an environment variable, distinguishing "unset" from
// "set to empty".  Unset yields defaultVal; explicitly empty yields empty.
// That distinction matters for settings whose default is non-empty and
// whose disabled state is empty — without it there would be no way to turn
// the setting off from the environment.
func lookupString(key, defaultVal string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return defaultVal
}

// parseBoolDefault is parseBool with an explicit default for the unset
// case.  Needed for flags that default to true, where parseBool's "empty
// means false" rule would invert the intent.  Both spellings are accepted
// explicitly so an operator can pin either state in config management
// rather than relying on absence; anything unrecognised falls back to
// defaultVal, matching the "garbage means default" pattern used by the
// other parse helpers in this file.
func parseBoolDefault(s string, defaultVal bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return defaultVal
}

// parseGoDuration reads a Go time.Duration string ("30m", "12h", "168h").
// Returns defaultVal for an empty string, parse failure, or non-positive
// result — matching the "fall back to safe default on garbage" pattern
// of the other parse helpers in this file.
//
// Note: time.ParseDuration's unit set is ns/us/µs/ms/s/m/h.  "d" and "w"
// are NOT supported, despite being the units operators naturally reach
// for.  The README explicitly tells them to write "168h" for a week;
// this helper does no translation of its own to keep the format stable
// with anything else that reads the same env var.
func parseGoDuration(s string, defaultVal time.Duration) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return defaultVal
	}
	return d
}

// parseAuthTokens reads token configuration from three sources in priority
// order and merges them into a single digest→identity map.  Later sources
// override earlier ones if they specify the same digest.
//
// Sources, lowest to highest priority:
//
//  1. MCP_AUTH_TOKEN          single token, identity defaults to "default"
//  2. MCP_AUTH_TOKENS         comma-separated "identity:token" pairs
//  3. MCP_AUTH_TOKEN_FILE     file path; one "identity:token" per line,
//     '#' comments and blank lines ignored
//
// Why three sources: MCP_AUTH_TOKEN keeps single-tenant deployments working
// with no config change. MCP_AUTH_TOKENS is for small static fleets that
// fit in env. MCP_AUTH_TOKEN_FILE is for anything bigger or when you want
// to mount tokens from a secret manager (the file can be on tmpfs / a
// Docker secret / a Kubernetes projected volume).
//
// Every token must satisfy minAuthTokenLen.  Empty identity is rejected.
// Identity ":" token uses strings.Cut on the first colon so tokens
// themselves may contain colons; identities may not.
func parseAuthTokens() (map[tokenDigest]string, error) {
	out := make(map[tokenDigest]string)

	if t := strings.TrimSpace(os.Getenv("MCP_AUTH_TOKEN")); t != "" {
		if err := addAuthToken(out, "default", t, "MCP_AUTH_TOKEN"); err != nil {
			return nil, err
		}
	}

	if v := os.Getenv("MCP_AUTH_TOKENS"); v != "" {
		for i, pair := range strings.Split(v, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			id, tok, ok := strings.Cut(pair, ":")
			if !ok {
				return nil, fmt.Errorf("MCP_AUTH_TOKENS entry %d: expected 'identity:token', got %q", i+1, pair)
			}
			id = strings.TrimSpace(id)
			tok = strings.TrimSpace(tok)
			if id == "" {
				return nil, fmt.Errorf("MCP_AUTH_TOKENS entry %d: empty identity", i+1)
			}
			if err := addAuthToken(out, id, tok, "MCP_AUTH_TOKENS"); err != nil {
				return nil, err
			}
		}
	}

	if path := strings.TrimSpace(os.Getenv("MCP_AUTH_TOKEN_FILE")); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("MCP_AUTH_TOKEN_FILE %q: %w", path, err)
		}
		for i, raw := range strings.Split(string(b), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			id, tok, ok := strings.Cut(line, ":")
			if !ok {
				return nil, fmt.Errorf("%s line %d: expected 'identity:token'", path, i+1)
			}
			id = strings.TrimSpace(id)
			tok = strings.TrimSpace(tok)
			if id == "" {
				return nil, fmt.Errorf("%s line %d: empty identity", path, i+1)
			}
			if err := addAuthToken(out, id, tok, path); err != nil {
				return nil, fmt.Errorf("%s line %d: %w", path, i+1, err)
			}
		}
	}

	return out, nil
}

// addAuthToken stores the SHA-256 of ("Bearer "+token) → identity, after
// validating the token meets the minimum length.  The source argument is
// for the error message only.
func addAuthToken(m map[tokenDigest]string, identity, token, source string) error {
	if len(token) < minAuthTokenLen {
		return fmt.Errorf("%s: token for identity %q is %d characters, need at least %d (use `openssl rand -hex 32`)",
			source, identity, len(token), minAuthTokenLen)
	}
	m[sha256.Sum256([]byte("Bearer "+token))] = identity
	return nil
}

// parseSharedSecretToken reads a single-shared-secret bearer token from envVar
// and returns the digest set an auth middleware looks it up in, or nil when the
// variable is unset.
//
// Backs both MCP_HEALTH_TOKEN and MCP_METRICS_TOKEN. These are shared secrets
// rather than per-caller credentials — they carry no identity, so a set is the
// right shape, not the digest→identity map AuthTokens uses. Both are validated
// against the same minAuthTokenLen minimum, and both are stored as the SHA-256
// of the full "Bearer "+token header value so the middleware can look them up
// with the same fixed-size, timing-safe digest comparison used by requireAuth.
// The raw token is never retained.
//
// Kept as one function rather than two near-identical ones so a change to the
// storage scheme — the "Bearer " prefix, the digest, the length floor — cannot
// land on one endpoint's credential and miss the other's.
func parseSharedSecretToken(envVar string) (map[tokenDigest]struct{}, error) {
	raw := strings.TrimSpace(os.Getenv(envVar))
	if raw == "" {
		return nil, nil
	}
	if len(raw) < minAuthTokenLen {
		return nil, fmt.Errorf("%s is %d characters, need at least %d (use `openssl rand -hex 32`)",
			envVar, len(raw), minAuthTokenLen)
	}
	return map[tokenDigest]struct{}{sha256.Sum256([]byte("Bearer " + raw)): {}}, nil
}

// parseHealthToken reads MCP_HEALTH_TOKEN. Unset leaves /health open — the
// historical default.
func parseHealthToken() (map[tokenDigest]struct{}, error) {
	return parseSharedSecretToken("MCP_HEALTH_TOKEN")
}

// parseMetricsToken reads MCP_METRICS_TOKEN. Unset closes /metrics entirely —
// the endpoint 401s every caller, including ones holding a valid MCP token.
// See Config.MetricsToken and requireMetricsAuth.
func parseMetricsToken() (map[tokenDigest]struct{}, error) {
	return parseSharedSecretToken("MCP_METRICS_TOKEN")
}

// countIdentities returns the number of distinct identities in m.
// Used by the startup banner; an identity may appear under multiple
// digests during token rotation ("alice:old", "alice:new" both valid).
func countIdentities(m map[tokenDigest]string) int {
	seen := make(map[string]struct{}, len(m))
	for _, id := range m {
		seen[id] = struct{}{}
	}
	return len(seen)
}

// parseDuration reads an integer number of seconds from s, returning
// defaultVal if s is empty, malformed, or non-positive.  Uses
// strconv.ParseInt (not fmt.Sscan) so trailing garbage like "300abc" is
// rejected rather than silently parsed as 300 — matching the
// "fall back to safe default on garbage" pattern of the other helpers.
func parseDuration(s string, defaultVal time.Duration) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultVal
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return defaultVal
	}
	return time.Duration(n)
}

// parseInt64 reads an integer from s, returning defaultVal if s is empty,
// malformed, or non-positive.  Uses strconv.ParseInt (not fmt.Sscan) so a
// value like "1000xyz" is rejected rather than truncated to 1000.
func parseInt64(s string, defaultVal int64) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultVal
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return defaultVal
	}
	return n
}

// parseInt is parseInt64 for config fields typed as int.  bitSize 0 tells
// strconv.ParseInt to bound the parse to the platform's int width, so a
// value that would not fit becomes a parse error and falls back to the
// default — the same "safe default on garbage" behaviour as the other
// helpers — instead of the silent truncation an int(parseInt64(...))
// conversion would perform on 32-bit platforms (CodeQL:
// incorrect-integer-conversion).  On the 64-bit deployment targets the
// two are behaviourally identical.
func parseInt(s string, defaultVal int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultVal
	}
	n, err := strconv.ParseInt(s, 10, 0)
	if err != nil || n <= 0 {
		return defaultVal
	}
	return int(n)
}

// parseFloat64 reads a floating-point value from s, returning defaultVal
// when s is empty, malformed, or negative.  Zero is allowed and meaningful
// — for MCP_RATE_LIMIT_RPS it means "disable the limiter" — so the
// rejection threshold is strictly < 0, unlike parseInt64 which rejects
// non-positive.
func parseFloat64(s string, defaultVal float64) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return defaultVal
	}
	return v
}

// parseCSV splits s on commas, trims whitespace around each entry, and
// drops empties.  Used for MCP_RATE_LIMIT_EXEMPT — a small list of
// identities — where a hand-edited env value can easily acquire spaces
// or a trailing comma.  Returns nil for empty input so callers can
// range over the result without checking first.
func parseCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func setupLogger(cfg Config) {
	switch strings.ToLower(cfg.LogLevel) {
	case "off", "none", "disable", "disabled":
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
		return
	}

	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(cfg.LogFormat) == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}
