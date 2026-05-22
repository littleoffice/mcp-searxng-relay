package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── tokenBucket arithmetic ────────────────────────────────────────────────────

// A fresh bucket admits its first request and returns no retry hint.
func TestTokenBucket_FirstCallStartsFull(t *testing.T) {
	b := &tokenBucket{}
	ok, retry := b.allow(1.0, 5)
	if !ok {
		t.Fatalf("first call on a fresh bucket should be allowed")
	}
	if retry != 0 {
		t.Errorf("retry should be zero when allowed, got %s", retry)
	}
}

// A burst of `burst` requests in quick succession all pass; the
// (burst+1)-th is denied.
func TestTokenBucket_BurstThenDeny(t *testing.T) {
	b := &tokenBucket{}
	for i := 0; i < 5; i++ {
		ok, _ := b.allow(1.0, 5)
		if !ok {
			t.Fatalf("call %d within burst should be allowed", i+1)
		}
	}
	ok, retry := b.allow(1.0, 5)
	if ok {
		t.Errorf("burst+1 call should be denied")
	}
	if retry <= 0 {
		t.Errorf("denied call must include a non-zero retry, got %s", retry)
	}
}

// After exhausting the burst, waiting longer than the regeneration
// interval restores at least one token.  Uses a 10 rps rate so the
// test completes in well under a second.
func TestTokenBucket_RefillsOverTime(t *testing.T) {
	b := &tokenBucket{}
	for i := 0; i < 5; i++ {
		b.allow(10.0, 5)
	}
	if ok, _ := b.allow(10.0, 5); ok {
		t.Fatalf("immediate post-burst call should be denied")
	}
	time.Sleep(150 * time.Millisecond) // > 100ms = one token at 10 rps
	if ok, _ := b.allow(10.0, 5); !ok {
		t.Errorf("call after refill window should be allowed")
	}
}

// Retry-After is at least one second even when sub-second math would
// suggest less — Retry-After ships as an integer second count, and
// "0" is the wrong answer for a denied request.
func TestTokenBucket_RetryAtLeastOneSecond(t *testing.T) {
	b := &tokenBucket{}
	b.allow(1000.0, 1)
	_, retry := b.allow(1000.0, 1)
	if retry < time.Second {
		t.Errorf("retry should be clamped to >= 1s, got %s", retry)
	}
}

// burst < 1 is nonsensical (no request would ever pass) but easy to
// produce by accident — clamp to 1.
func TestNewRateLimiter_BurstClampedToOne(t *testing.T) {
	rl := newRateLimiter(1.0, 0, nil)
	if rl.burst != 1 {
		t.Errorf("burst should clamp to 1 minimum, got %d", rl.burst)
	}
}

// ── rateLimiter behaviour ─────────────────────────────────────────────────────

func TestRateLimiter_DisabledAllowsEverything(t *testing.T) {
	rl := newRateLimiter(0, 10, nil)
	if rl.enabled() {
		t.Fatalf("rps=0 should disable the limiter")
	}
	for i := 0; i < 1000; i++ {
		if ok, _ := rl.allow("anything"); !ok {
			t.Fatalf("disabled limiter denied call %d", i+1)
		}
	}
}

// Two distinct keys get independent buckets, so exhausting one does not
// affect the other.
func TestRateLimiter_PerKeyIsolation(t *testing.T) {
	rl := newRateLimiter(1.0, 3, nil)
	for i := 0; i < 3; i++ {
		rl.allow("id:alice")
	}
	if ok, _ := rl.allow("id:alice"); ok {
		t.Fatalf("alice's bucket should be exhausted")
	}
	if ok, _ := rl.allow("id:bob"); !ok {
		t.Errorf("bob's bucket should still be full")
	}
}

// Concurrent access to the same bucket must be race-free.  Run under
// `go test -race`.  We don't assert on the allow/deny split (timing-
// dependent), only that nothing panics or trips the race detector.
func TestRateLimiter_ConcurrentSameKey(t *testing.T) {
	rl := newRateLimiter(100.0, 50, nil)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				rl.allow("id:hot")
			}
		}()
	}
	wg.Wait()
}

// Regression test for the bucketFor() lost-bucket race.  Before the fix
// (Get → Add → Get pattern), two goroutines could both miss in Get,
// both allocate, both Add (the second overwriting the first), and each
// return a *different* bucket pointer.  Whoever lost the race silently
// owned an orphaned bucket — their request consumed a token from a
// bucket that no future caller would ever see, while subsequent callers
// keyed on the winner's bucket got the full burst again.  Effective
// outcome: one extra request leaked through per first-contact race
// window.
//
// We aggregate many independent races: 1000 distinct keys, 4 goroutines
// per key released from a single starting gun.  The invariant is per-
// key: every goroutine querying the same key must receive the same
// *tokenBucket pointer.  Any divergence is a race hit.
//
// Note that this is a *probabilistic* regression test for a logic race
// (the LRU's internal lock means `go test -race` won't flag it).  The
// race manifests reliably on multi-core hosts and under -count=N stress;
// on a single-CPU sandbox without true parallelism the buggy code may
// still pass because the scheduler doesn't interleave the Get/Add
// sequence between two goroutines.  Treat a failure here as a hard
// regression; treat a single pass as one data point.
func TestBucketFor_ConcurrentFirstContactConvergesPerKey(t *testing.T) {
	rl := newRateLimiter(1.0, 5, nil)
	const Keys = 1000
	const PerKey = 4

	results := make([][]*tokenBucket, Keys)
	for k := range results {
		results[k] = make([]*tokenBucket, PerKey)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for k := 0; k < Keys; k++ {
		for i := 0; i < PerKey; i++ {
			wg.Add(1)
			go func(k, i int) {
				defer wg.Done()
				<-start
				results[k][i] = rl.bucketFor(fmt.Sprintf("id:k%d", k))
			}(k, i)
		}
	}
	close(start)
	wg.Wait()

	divergent := 0
	for k := 0; k < Keys; k++ {
		first := results[k][0]
		for i := 1; i < PerKey; i++ {
			if results[k][i] != first {
				divergent++
				break
			}
		}
	}
	if divergent > 0 {
		t.Errorf("%d/%d keys had divergent bucket pointers across concurrent callers — lost-bucket race",
			divergent, Keys)
	}
}

// Behavioural counterpart: with burst=1 and many goroutines firing
// simultaneously against an uninitialised key, exactly ONE request must
// be allowed.  More than one would mean two goroutines briefly owned
// independent buckets and each charged its own fresh burst.  Same
// environmental caveat as above: deterministic post-fix, probabilistic
// pre-fix.
func TestRateLimiter_ConcurrentFirstContactBurstEnforced(t *testing.T) {
	// 0.0001 rps means no measurable refill during the test window.
	rl := newRateLimiter(0.0001, 1, nil)
	const N = 500

	var allowed atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, _ := rl.allow("id:contended"); ok {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := allowed.Load(); got != 1 {
		t.Errorf("with burst=1 and %d concurrent callers on one key, expected exactly 1 allowed, got %d (lost-bucket race)",
			N, got)
	}
}

// ── describe() banner output ──────────────────────────────────────────────────

func TestRateLimiter_DescribeDisabled(t *testing.T) {
	rl := newRateLimiter(0, 0, nil)
	if got := rl.describe(); got != "disabled" {
		t.Errorf("describe() = %q, want %q", got, "disabled")
	}
}

func TestRateLimiter_DescribeEnabled(t *testing.T) {
	rl := newRateLimiter(5.0, 10, nil)
	got := rl.describe()
	if !strings.Contains(got, "5 rps") || !strings.Contains(got, "burst 10") {
		t.Errorf("describe() = %q, want rps + burst", got)
	}
}

func TestRateLimiter_DescribeFractionalRPS(t *testing.T) {
	rl := newRateLimiter(0.5, 2, nil)
	got := rl.describe()
	if !strings.Contains(got, "0.5 rps") {
		t.Errorf("describe() = %q, want fractional rps preserved", got)
	}
}

func TestRateLimiter_DescribeWithExempt(t *testing.T) {
	rl := newRateLimiter(5.0, 10, []string{"prom", "ci"})
	got := rl.describe()
	if !strings.Contains(got, "2 exempt") {
		t.Errorf("describe() = %q, want '2 exempt' suffix", got)
	}
}

// ── callerKey scoping ─────────────────────────────────────────────────────────

// A request carrying a recognised bearer token keys on the identity.
func TestCallerKey_IdentityWhenAuthed(t *testing.T) {
	digest := sha256.Sum256([]byte("Bearer secret"))
	s := &Server{config: Config{AuthTokens: map[tokenDigest]string{digest: "alice"}}}
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Authorization", "Bearer secret")
	r.RemoteAddr = "10.1.2.3:54321"
	key, identity := s.callerKey(r)
	if identity != "alice" {
		t.Errorf("identity = %q, want %q", identity, "alice")
	}
	if key != "id:alice" {
		t.Errorf("key = %q, want %q", key, "id:alice")
	}
}

// An unrecognised token falls back to the IP key, with the port stripped.
func TestCallerKey_IPFallbackOnUnknownToken(t *testing.T) {
	digest := sha256.Sum256([]byte("Bearer good"))
	s := &Server{config: Config{AuthTokens: map[tokenDigest]string{digest: "alice"}}}
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	r.RemoteAddr = "10.1.2.3:54321"
	key, identity := s.callerKey(r)
	if identity != "" {
		t.Errorf("identity should be empty for unknown token, got %q", identity)
	}
	if key != "ip:10.1.2.3" {
		t.Errorf("key = %q, want %q", key, "ip:10.1.2.3")
	}
}

// A request with no Authorization header falls back to the IP key.
// Also exercises IPv6 RemoteAddr formatting.
func TestCallerKey_IPFallbackOnNoAuth(t *testing.T) {
	digest := sha256.Sum256([]byte("Bearer good"))
	s := &Server{config: Config{AuthTokens: map[tokenDigest]string{digest: "alice"}}}
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "[2001:db8::1]:5000"
	key, identity := s.callerKey(r)
	if identity != "" {
		t.Errorf("identity should be empty for no auth, got %q", identity)
	}
	if key != "ip:2001:db8::1" {
		t.Errorf("IPv6 key = %q, want %q", key, "ip:2001:db8::1")
	}
}

// ── middleware behaviour ──────────────────────────────────────────────────────

// When disabled, the middleware is a pass-through and the next handler
// always runs.  Importantly the disabled middleware should be the same
// http.Handler we passed in — no allocation, no per-request bookkeeping.
func TestRateLimitMiddleware_DisabledPassesThrough(t *testing.T) {
	s := &Server{rateLimiter: newRateLimiter(0, 0, nil)}
	called := 0
	h := s.rateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	}))
	for i := 0; i < 100; i++ {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if called != 100 {
		t.Errorf("disabled middleware called next %d times, want 100", called)
	}
}

// Enabled: bursting past capacity yields 429 with a Retry-After header
// and bumps the rejection metric.
func TestRateLimitMiddleware_RejectsWith429(t *testing.T) {
	s := &Server{
		config:      Config{AuthTokens: nil}, // unauthed -> IP keying
		rateLimiter: newRateLimiter(1.0, 2, nil),
	}
	h := s.rateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	doReq := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if rr := doReq(); rr.Code != http.StatusOK {
		t.Fatalf("first call should pass, got %d", rr.Code)
	}
	if rr := doReq(); rr.Code != http.StatusOK {
		t.Fatalf("second call (within burst) should pass, got %d", rr.Code)
	}
	rr := doReq()
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("third call should 429, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Errorf("429 response missing Retry-After header")
	}
	if s.metrics.RateLimitRejections.Load() != 1 {
		t.Errorf("rejection counter = %d, want 1", s.metrics.RateLimitRejections.Load())
	}
}

// Exempt identities bypass the limiter completely — even with burst=1
// and many sequential calls, no 429 is ever returned, and the rejection
// counter stays at zero.
func TestRateLimitMiddleware_ExemptIdentityBypasses(t *testing.T) {
	digest := sha256.Sum256([]byte("Bearer monitor-token"))
	s := &Server{
		config:      Config{AuthTokens: map[tokenDigest]string{digest: "prom"}},
		rateLimiter: newRateLimiter(1.0, 1, []string{"prom"}),
	}
	h := s.rateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Authorization", "Bearer monitor-token")
		r.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("exempt identity got %d on call %d, want 200", w.Code, i+1)
		}
	}
	if s.metrics.RateLimitRejections.Load() != 0 {
		t.Errorf("rejection counter = %d, want 0 for exempt", s.metrics.RateLimitRejections.Load())
	}
}

// Two distinct IPs hitting the same endpoint use independent buckets.
// Exhausting one does not affect the other.
func TestRateLimitMiddleware_PerIPIsolation(t *testing.T) {
	s := &Server{
		config:      Config{AuthTokens: nil},
		rateLimiter: newRateLimiter(1.0, 1, nil),
	}
	h := s.rateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	hit := func(ip string) int {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = ip
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if got := hit("10.0.0.1:1"); got != http.StatusOK {
		t.Fatalf("ip A first call: got %d", got)
	}
	if got := hit("10.0.0.1:2"); got != http.StatusTooManyRequests {
		t.Errorf("ip A burst exhausted, second call: got %d", got)
	}
	if got := hit("10.0.0.2:1"); got != http.StatusOK {
		t.Errorf("ip B should have a fresh bucket: got %d", got)
	}
}
