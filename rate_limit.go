package main

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// ── Rate limiting ─────────────────────────────────────────────────────────────
//
// Per-caller token-bucket throttle applied to the MCP root and /metrics.
// Two scopes: when the request carries a recognised bearer token the bucket
// is keyed by identity ("id:<name>"), and otherwise by the remote IP
// ("ip:<addr>").  This gives authenticated callers a usage budget that is
// shared across all sources presenting the same token, and gives a brute-
// force defence against unauthenticated POST floods from a single IP.
//
// Why stdlib only: a token bucket is small (~30 lines of arithmetic), and
// the project explicitly treats its dependency tree as a security property
// (see supply-chain.md).  golang.org/x/time/rate would be the natural
// alternative; it adds blocking/reservation APIs we wouldn't use and one
// more dependency to track.
//
// Bucket storage is an LRU keyed by the scope string above, capped at
// rateBucketCacheSize.  Identities are bounded by the auth-token table so
// they all fit comfortably; the cap exists to bound IP-keyed entries when
// an attacker rotates source addresses.  Eviction of an idle bucket has
// no semantic effect — the next request just refills a fresh bucket.

// rateBucketCacheSize caps the number of distinct caller buckets we hold
// in memory.  With ~40 bytes per bucket, 10k entries is ~400 KiB, which
// is well below any reasonable container memory budget and far above any
// legitimate caller count.  When the cap is reached the LRU evicts the
// least-recently-used entry; this only matters under IP-rotation attacks,
// where the right behaviour is bounded memory not perfect accounting.
const rateBucketCacheSize = 10_000

// tokenBucket is a single-caller token bucket.  Tokens regenerate at
// `rate` per second up to a maximum of `burst`.  Each Allow() call
// consumes one token if available; otherwise it returns a Retry-After
// hint computed from the regeneration rate.
//
// The mutex protects tokens / last from concurrent updates — the same
// caller can have several in-flight requests in HTTP mode, so this is
// not theoretical.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64   // current token count (fractional, refills continuously)
	last   time.Time // wall clock at which `tokens` was last updated
}

// allow decides whether one request should pass.  Returns (true, 0) when
// a token is available; otherwise (false, retry) where retry is the time
// until at least one token will have regenerated.  rate is tokens per
// second; burst is the bucket capacity.
//
// We use time.Since(b.last) rather than now.Sub(b.last) so the bucket
// stays correct even if the wall clock jumps — Go's time package keeps
// a monotonic reading inside time.Time values created with time.Now(),
// and Since uses it.  Negative elapsed (clock-fiddling, very rare) is
// clamped to zero rather than withdrawing tokens.
func (b *tokenBucket) allow(rate float64, burst int) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if b.last.IsZero() {
		// Fresh bucket — start full so the very first request always
		// passes regardless of rate.  This matches operator expectations:
		// "RPS 5" should not mean the first call waits 200ms.
		b.tokens = float64(burst)
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(float64(burst), b.tokens+elapsed*rate)
		}
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens -= 1
		return true, 0
	}

	// Time to regenerate one full token.  Round up to whole seconds
	// because Retry-After is delivered as an integer in the HTTP
	// response header — sub-second precision would be discarded
	// anyway and "0" is the wrong answer for a denied request.
	deficit := 1 - b.tokens
	retry := time.Duration(math.Ceil(deficit/rate)) * time.Second
	if retry < time.Second {
		retry = time.Second
	}
	return false, retry
}

// rateLimiter is the per-server throttle.  Holds the configuration and a
// bounded LRU of per-caller buckets.  Zero-valued (rate == 0) means the
// feature is disabled and Allow() short-circuits to "allow everything".
type rateLimiter struct {
	rate    float64
	burst   int
	exempt  map[string]struct{}              // identity names that bypass the limiter
	buckets *lru.Cache[string, *tokenBucket] // keyed by "id:<name>" or "ip:<addr>"
}

// newRateLimiter constructs a limiter from already-validated config
// values.  rate <= 0 disables the limiter.  burst is clamped to >= 1
// when the limiter is enabled.  exempt entries get a fast-path bypass.
func newRateLimiter(rate float64, burst int, exempt []string) *rateLimiter {
	rl := &rateLimiter{rate: rate, burst: burst, exempt: make(map[string]struct{}, len(exempt))}
	if rate <= 0 {
		return rl
	}
	if burst < 1 {
		burst = 1
	}
	rl.burst = burst
	for _, id := range exempt {
		rl.exempt[id] = struct{}{}
	}
	// Cache construction only fails for size <= 0, which we guarantee here.
	c, err := lru.New[string, *tokenBucket](rateBucketCacheSize)
	if err != nil {
		panic("failed to initialise rate-limiter LRU: " + err.Error())
	}
	rl.buckets = c
	return rl
}

// enabled reports whether this limiter is active.
func (rl *rateLimiter) enabled() bool {
	return rl != nil && rl.rate > 0
}

// bucketFor returns the (possibly newly-created) bucket for key.
//
// Two paths:
//
//   - Fast (existing bucket): a single LRU Get, which is the entire cost
//     for every request after the first one from a given caller.  No
//     allocation, no atomic create dance.
//
//   - Slow (first contact, or post-eviction): PeekOrAdd is the LRU's
//     atomic load-or-store primitive — under a single acquisition of the
//     LRU's internal lock it either returns the existing entry or
//     installs the candidate we passed.  This is what closes the
//     lost-bucket race: a naive Get-then-Add lets two goroutines each
//     miss in Get, each create a fresh bucket, and the second Add
//     overwrite the first.  The two goroutines then return *different*
//     pointers, each gets a fresh full-burst bucket, and the rate limit
//     fails to enforce for that race window (one extra request leaks
//     through per first-contact race).  PeekOrAdd makes the create-or-
//     load operation atomic so every concurrent caller for a key
//     converges on the same bucket pointer.
//
// PeekOrAdd is preferred over ContainsOrAdd because it returns the
// existing value directly, saving the extra Get call when we lost the
// race.  Peek doesn't update the LRU recency on found — that's fine here
// because allow() reaches the bucket via Get() on the next request,
// which does promote it.
func (rl *rateLimiter) bucketFor(key string) *tokenBucket {
	if b, ok := rl.buckets.Get(key); ok {
		return b
	}
	candidate := &tokenBucket{}
	if existing, found, _ := rl.buckets.PeekOrAdd(key, candidate); found {
		return existing
	}
	return candidate
}

// allow consults the bucket for key and decides whether to admit the
// request.  Called by the middleware; tests can drive it directly.
func (rl *rateLimiter) allow(key string) (bool, time.Duration) {
	if !rl.enabled() {
		return true, 0
	}
	return rl.bucketFor(key).allow(rl.rate, rl.burst)
}

// callerKey returns the bucket key for a request, plus the identity (or
// "" if the caller is unauthenticated or its token is unrecognised) for
// logging.  Identity matching mirrors requireAuth: hash the Authorization
// header and look it up in the configured table.  We deliberately do
// not skip the IP fallback when requireAuth itself is disabled (stdio
// mode never reaches HTTP middleware, so in practice this matters only
// in tests).
//
// The IP key uses the host part of RemoteAddr only — including the port
// would create a fresh bucket per outbound connection, defeating the
// whole point of the IP fallback.
func (s *Server) callerKey(r *http.Request) (key, identity string) {
	if len(s.config.AuthTokens) > 0 {
		got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if id, ok := s.config.AuthTokens[got]; ok {
			return "id:" + id, id
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr without a port is unexpected but handled rather
		// than panicking — treat the whole string as the host.
		host = r.RemoteAddr
	}
	return "ip:" + host, ""
}

// rateLimit wraps next with the per-caller throttle.  No-op when the
// limiter is disabled.  Rejections emit a warn-level log line carrying
// the same fields requireAuth uses ("remote", "method", "path", and
// "identity" when known) so audit forensics can join refusals to the
// surrounding traffic for the same caller.
//
// 429 with a Retry-After header is RFC 6585 §4.  We also set the header
// on the limiter's response body for callers that read body before
// headers (paranoia — Go's stdlib doesn't, but third-party clients vary).
func (s *Server) rateLimit(next http.Handler) http.Handler {
	if !s.rateLimiter.enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, identity := s.callerKey(r)
		// Exempt identities bypass the limiter entirely.  We don't
		// bother creating a bucket for them; the exempt list is
		// typically a handful of names (monitoring scrapers, CI).
		if identity != "" {
			if _, ok := s.rateLimiter.exempt[identity]; ok {
				next.ServeHTTP(w, r)
				return
			}
		}
		ok, retry := s.rateLimiter.allow(key)
		if !ok {
			s.metrics.RateLimitRejections.Add(1)
			slog.Warn("rate limit exceeded",
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
				"identity", identity,
				"retry_after", retry.String())
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitDescription renders a human-readable limiter summary for the
// startup banner.  "disabled" when off; otherwise "<rps> rps, burst N"
// plus the exempt count when non-empty.  Kept here next to the limiter
// itself so banner formatting and behaviour stay in sync.
func (rl *rateLimiter) describe() string {
	if !rl.enabled() {
		return "disabled"
	}
	// Trim trailing zeros: "5 rps" reads better than "5.000000 rps",
	// but "0.5 rps" must keep its precision.  strconv.FormatFloat
	// with -1 precision does exactly this.
	rate := strconv.FormatFloat(rl.rate, 'f', -1, 64)
	desc := fmt.Sprintf("%s rps, burst %d", rate, rl.burst)
	if n := len(rl.exempt); n > 0 {
		desc += fmt.Sprintf(" (%d exempt)", n)
	}
	return desc
}
