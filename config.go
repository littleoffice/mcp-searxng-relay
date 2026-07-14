package main

import (
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
	SearxngURL             string
	AuthUsername           string
	AuthPassword           string
	UserAgent              string
	LogLevel               string
	LogFormat              string
	AuthTokens             map[tokenDigest]string // digest → identity, populated by parseAuthTokens
	Stateless              bool                   // MCP_STATELESS=true → SDK skips session tracking
	SessionMaxAge          time.Duration          // MCP_SESSION_MAX_AGE: idle-session reap age (stateful only)
	SessionJanitorInterval time.Duration          // MCP_SESSION_JANITOR_INTERVAL: how often the janitor wakes
	CacheTTL               time.Duration
	CacheMaxEntries        int
	MaxBodyBytes           int64
	MaxPDFBytes            int64
	MaxOfficeBytes         int64
	MaxImageBytes          int64
	MaxExtractedChars      int // MAX_EXTRACTED_CHARS: cap on extracted text cached per URL
	RateLimitRPS           float64  // MCP_RATE_LIMIT_RPS: per-caller sustained rate (requests/sec); 0 disables
	RateLimitBurst         int      // MCP_RATE_LIMIT_BURST: token-bucket capacity
	RateLimitExempt        []string // MCP_RATE_LIMIT_EXEMPT: identities bypassed entirely (e.g. monitoring)

	// Fetch allow-list (opt-in SSRF widening). Both empty by default, which
	// keeps the fetch tool restricted to public IPs. Raw values are read here;
	// FetchACL is the compiled, validated form populated in main() (see
	// newFetchACL). Storing the raw lists too keeps the startup banner and any
	// future /config introspection honest about what was configured.
	FetchAllowedHosts []string  // FETCH_ALLOWED_HOSTS: hostnames exempt from the public-IP check
	FetchAllowedCIDRs []string  // FETCH_ALLOWED_CIDRS: IP ranges treated as reachable
	FetchACL          *fetchACL // compiled form; nil until main() validates the two lists
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
	c.CacheMaxEntries = int(parseInt64(os.Getenv("CACHE_MAX_ENTRIES"), 1_000))
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
	c.MaxExtractedChars = int(parseInt64(os.Getenv("MAX_EXTRACTED_CHARS"), 1_000_000))
	c.Stateless = parseBool(os.Getenv("MCP_STATELESS"))
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
	c.RateLimitBurst = int(parseInt64(os.Getenv("MCP_RATE_LIMIT_BURST"), int64(defaultBurst)))
	c.RateLimitExempt = parseCSV(os.Getenv("MCP_RATE_LIMIT_EXEMPT"))
	// Fetch allow-list — comma-separated. Parsed into raw slices here; the
	// CIDRs are compiled and validated in main() via newFetchACL so a bad
	// entry fails startup with a clear message instead of being silently
	// dropped. Empty (the default) leaves the strict public-only policy.
	c.FetchAllowedHosts = parseCSV(os.Getenv("FETCH_ALLOWED_HOSTS"))
	c.FetchAllowedCIDRs = parseCSV(os.Getenv("FETCH_ALLOWED_CIDRS"))
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
