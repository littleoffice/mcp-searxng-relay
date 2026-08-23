package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── source table ──────────────────────────────────────────────────────────────

func TestFetchHistoryOrderingIsNewestFirst(t *testing.T) {
	h := &fetchHistory{}
	for i := 1; i <= 3; i++ {
		h.appendRecord(fetchRecord{URL: "https://example.com/" + string(rune('a'+i-1))})
	}

	got, total, evicted := h.list()
	if total != 3 || evicted != 0 {
		t.Fatalf("total = %d, evicted = %d, want 3 and 0", total, evicted)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].URL != "https://example.com/c" {
		t.Errorf("newest = %q, want .../c", got[0].URL)
	}
	if got[2].URL != "https://example.com/a" {
		t.Errorf("oldest = %q, want .../a", got[2].URL)
	}
	// Sequence numbers are assigned in append order, not list order.
	if got[0].Seq != 3 || got[2].Seq != 1 {
		t.Errorf("seq = %d..%d, want 3..1", got[0].Seq, got[2].Seq)
	}
}

func TestFetchHistoryEvictsAndReportsTrueTotals(t *testing.T) {
	h := &fetchHistory{}
	const n = fetchHistoryEntries + 17
	for i := 1; i <= n; i++ {
		h.appendRecord(fetchRecord{URL: fmt.Sprintf("https://example.com/%d", i), CharsRead: i})
	}

	got, total, evicted := h.list()
	if total != n {
		t.Errorf("total = %d, want %d — the count of everything ever appended, not what was retained", total, n)
	}
	if len(got) != fetchHistoryEntries {
		t.Fatalf("retained = %d, want %d", len(got), fetchHistoryEntries)
	}
	if want := n - fetchHistoryEntries; evicted != want {
		t.Errorf("evicted = %d, want %d — the count is what tells the caller the list is no longer complete", evicted, want)
	}
	if got[0].CharsRead != n {
		t.Errorf("newest = %d, want %d", got[0].CharsRead, n)
	}
	if want := n - fetchHistoryEntries + 1; got[len(got)-1].CharsRead != want {
		t.Errorf("oldest retained = %d, want %d", got[len(got)-1].CharsRead, want)
	}
	// Sequence numbers must keep climbing past the table size, otherwise
	// since_seq would silently re-serve entries after an eviction.
	if got[0].Seq != n {
		t.Errorf("newest seq = %d, want %d", got[0].Seq, n)
	}
}

// The regression that motivated one slot per source: a paginated read is one
// source and many fetches.  Under slot-per-fetch, six windows of one document
// cost six of the fifty slots, and a caller who paged through a few long
// documents could lose sources it had genuinely cited while the same URL sat
// in the table six times over.
func TestFetchHistoryRepeatFetchesDoNotConsumeSlots(t *testing.T) {
	h := &fetchHistory{}

	for i := 0; i < fetchHistoryEntries; i++ {
		u := fmt.Sprintf("https://example.com/source/%d", i)
		for window := 0; window < 6; window++ {
			h.appendRecord(fetchRecord{URL: u, Outcome: "ok", Read: readDepthPartial})
		}
	}

	got, total, evicted := h.list()
	if len(got) != fetchHistoryEntries {
		t.Fatalf("retained = %d sources, want %d — repeat fetches are consuming slots", len(got), fetchHistoryEntries)
	}
	if evicted != 0 {
		t.Errorf("evicted = %d, want 0 — nothing is dropped while the source count fits", evicted)
	}
	if want := fetchHistoryEntries * 6; total != want {
		t.Errorf("total = %d, want %d — total counts fetches, not sources", total, want)
	}
	if got[0].Fetches != 6 {
		t.Errorf("fetches = %d, want 6", got[0].Fetches)
	}
}

// Eviction goes by last touch, not by first sight.  A source re-read late in a
// task is the one most likely to be cited, and dropping it because it was
// first seen early is exactly the wrong choice.
func TestFetchHistoryEvictsLeastRecentlyTouched(t *testing.T) {
	h := &fetchHistory{}
	for i := 0; i < fetchHistoryEntries; i++ {
		h.appendRecord(fetchRecord{URL: fmt.Sprintf("https://example.com/%d", i)})
	}

	// Re-read the first source, then overflow the table by one.
	h.appendRecord(fetchRecord{URL: "https://example.com/0"})
	h.appendRecord(fetchRecord{URL: "https://example.com/new"})

	got, _, evicted := h.list()
	if evicted != 1 {
		t.Fatalf("evicted = %d, want 1", evicted)
	}
	held := make(map[string]bool, len(got))
	for _, r := range got {
		held[r.URL] = true
	}
	if !held["https://example.com/0"] {
		t.Error("dropped the re-fetched source: eviction is following insertion order, not recency")
	}
	if held["https://example.com/1"] {
		t.Error("expected the least recently touched source (.../1) to be the one dropped")
	}
	if !held["https://example.com/new"] {
		t.Error("the new source never made it into the table")
	}
}

func TestFetchHistoryConcurrentAppend(t *testing.T) {
	// The LRU protects its map, not the table behind the returned pointer.
	// Run with -race.
	h := &fetchHistory{}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.appendRecord(fetchRecord{URL: "https://example.com/x"})
			_, _, _ = h.list()
		}()
	}
	wg.Wait()

	got, total, _ := h.list()
	if total != 64 {
		t.Errorf("total = %d, want 64 — lost or double-counted appends", total)
	}
	if len(got) != 1 {
		t.Fatalf("sources = %d, want 1 — 64 fetches of one URL are one source", len(got))
	}
	if got[0].Fetches != 64 {
		t.Errorf("fetches = %d, want 64 — merges raced", got[0].Fetches)
	}
}

// ── merging repeat fetches ────────────────────────────────────────────────────

// The claim an entry supports is the deepest read ever achieved for that URL.
// Taking the newest record wholesale, as the old read-time dedup did, lets a
// metadata-only triage call downgrade a page that was already read in full —
// understating precisely the distinction this tool exists to carry.
func TestMergeKeepsDeepestRead(t *testing.T) {
	h := &fetchHistory{}
	h.appendRecord(fetchRecord{
		URL: "https://example.com/a", Tool: "searxng_read_url", Outcome: "ok",
		Read: readDepthFull, CharsRead: 18422, TotalChars: 18422, Title: "Article",
	})
	h.appendRecord(fetchRecord{
		URL: "https://example.com/a", Tool: "searxng_url_metadata", Outcome: "ok",
		Read: readDepthMetadata,
	})

	got, _, _ := h.list()
	if len(got) != 1 {
		t.Fatalf("sources = %d, want 1", len(got))
	}
	if got[0].Read != readDepthFull {
		t.Errorf("read = %q, want %q — a later metadata call does not un-read the page", got[0].Read, readDepthFull)
	}
	if got[0].CharsRead != 18422 || got[0].TotalChars != 18422 {
		t.Errorf("chars = %d/%d, want 18422/18422", got[0].CharsRead, got[0].TotalChars)
	}
	if got[0].Title != "Article" {
		t.Errorf("title = %q, want the one carried by the deeper read", got[0].Title)
	}
	// Recency fields still describe the most recent touch.
	if got[0].Seq != 2 || got[0].Tool != "searxng_url_metadata" {
		t.Errorf("seq/tool = %d/%q, want 2/searxng_url_metadata — recency comes from the newest fetch",
			got[0].Seq, got[0].Tool)
	}
	if got[0].Fetches != 2 {
		t.Errorf("fetches = %d, want 2", got[0].Fetches)
	}
}

// A re-fetch that fails does not erase the copy already returned.
func TestMergeSurvivesALaterFailure(t *testing.T) {
	h := &fetchHistory{}
	h.appendRecord(fetchRecord{URL: "https://example.com/a", Outcome: "ok", Read: readDepthFull, CharsRead: 900})
	h.appendRecord(fetchRecord{URL: "https://example.com/a", Outcome: "error", Read: readDepthNone, Err: "URL returned HTTP 503"})

	got, _, _ := h.list()
	if got[0].Outcome != "ok" || got[0].Read != readDepthFull {
		t.Errorf("outcome/read = %q/%q, want ok/full", got[0].Outcome, got[0].Read)
	}
	if got[0].Err != "" {
		t.Errorf("err = %q, want empty — outcome and error travel together or the row contradicts itself", got[0].Err)
	}
	if got[0].CharsRead != 900 {
		t.Errorf("chars_read = %d, want 900 — the failed re-fetch must not shrink what was read", got[0].CharsRead)
	}
}

// When nothing was ever read, equal depths resolve to the newer record, so the
// row carries the most recent failure rather than the first one.
func TestMergeKeepsNewestErrorWhenNothingWasEverRead(t *testing.T) {
	h := &fetchHistory{}
	h.appendRecord(fetchRecord{URL: "https://example.com/a", Outcome: "error", Read: readDepthNone, Err: "dial tcp: i/o timeout"})
	h.appendRecord(fetchRecord{URL: "https://example.com/a", Outcome: "error", Read: readDepthNone, Err: "URL returned HTTP 404"})

	got, _, _ := h.list()
	if len(got) != 1 {
		t.Fatalf("sources = %d, want 1", len(got))
	}
	if got[0].Err != "URL returned HTTP 404" {
		t.Errorf("err = %q, want the most recent failure", got[0].Err)
	}
}

// A merged entry has to stay filed under the URL it is reported as.  If the
// two diverge, eviction deletes the wrong index key: the stale key then points
// at a slot holding someone else's source, and the entry it used to name can
// never be merged into again.
func TestMergeKeepsIndexKeyAndCitableURLInStep(t *testing.T) {
	h := &fetchHistory{}
	h.appendRecord(fetchRecord{
		URL: "https://example.com/short", FinalURL: "https://www.example.com/full?id=7",
		Outcome: "ok", Read: readDepthFull,
	})
	h.appendRecord(fetchRecord{
		URL: "https://www.example.com/full?id=7", FinalURL: "https://www.example.com/full?id=7",
		Outcome: "ok", Read: readDepthFull,
	})

	got, _, _ := h.list()
	if len(got) != 1 {
		t.Fatalf("sources = %d, want 1 — a redirect target and a direct fetch of it are one source", len(got))
	}
	if key := citableURL(got[0]); key != "https://www.example.com/full?id=7" {
		t.Errorf("citable URL = %q, want the post-redirect URL", key)
	}
	if len(h.index) != 1 {
		t.Fatalf("index holds %d keys, want 1", len(h.index))
	}
	for key, slot := range h.index {
		if held := citableURL(h.entries[slot]); held != key {
			t.Errorf("index key %q points at an entry citable as %q", key, held)
		}
	}
}

// ── cap configuration ─────────────────────────────────────────────────────────

func TestHistoryEntriesConfigDefaultsAndRejectsNonsense(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want int
	}{
		{"", fetchHistoryEntries},
		{"200", 200},
		{"0", fetchHistoryEntries},
		{"-5", fetchHistoryEntries},
		{"plenty", fetchHistoryEntries},
	} {
		t.Setenv("MCP_HISTORY_ENTRIES", tc.env)
		if got := configFromEnv().HistoryEntries; got != tc.want {
			t.Errorf("MCP_HISTORY_ENTRIES=%q gave %d, want %d", tc.env, got, tc.want)
		}
	}
}

func TestHistoryHonoursConfiguredCap(t *testing.T) {
	s := &Server{history: newFetchHistoryCache(nil)}
	s.config.HistoryEntries = 3
	ctx := sourcesTestCtx("alice")

	for i := 1; i <= 5; i++ {
		s.recordFetch(ctx, fetchRecord{
			URL: fmt.Sprintf("https://example.com/%d", i), Outcome: "ok", Read: readDepthFull,
		})
	}

	got, total, evicted := s.historyFor(ctx).list()
	if len(got) != 3 {
		t.Fatalf("retained = %d, want 3 — the configured cap is not reaching the table", len(got))
	}
	if total != 5 || evicted != 2 {
		t.Errorf("total/evicted = %d/%d, want 5/2", total, evicted)
	}
	if got[0].URL != "https://example.com/5" {
		t.Errorf("newest = %q, want .../5", got[0].URL)
	}
	if n := s.metrics.HistoryEvictions.Load(); n != 2 {
		t.Errorf("mcp_history_evictions_total = %d, want 2", n)
	}
}

// A history built without a cap must be usable and sized to the default, not
// a zero-length table that silently drops everything written to it.
func TestHistoryZeroCapSizesToDefault(t *testing.T) {
	h := newFetchHistory(0)
	for i := 0; i <= fetchHistoryEntries; i++ {
		h.appendRecord(fetchRecord{URL: fmt.Sprintf("https://example.com/%d", i)})
	}

	got, _, evicted := h.list()
	if len(got) != fetchHistoryEntries {
		t.Fatalf("retained = %d, want the default %d", len(got), fetchHistoryEntries)
	}
	if evicted != 1 {
		t.Errorf("evicted = %d, want 1", evicted)
	}
}

// ── caller keying ─────────────────────────────────────────────────────────────

func TestHistoryKeySeparatesCallersSharingASessionID(t *testing.T) {
	// The case this guards: a stateless caller that sends no Mcp-Session-Id
	// header (since go-sdk v1.7.0 the SDK reads none of its own), or the
	// documented configuration where GetSessionID returns "".  Keying on
	// session alone would collapse every caller onto one history and hand one
	// tenant another's URLs.
	a := withSessionID(withIdentity(context.Background(), "alice"), "")
	b := withSessionID(withIdentity(context.Background(), "bob"), "")

	if historyKey(a) == historyKey(b) {
		t.Fatal("distinct identities with empty session IDs share a history key")
	}
}

// A plain "identity|session" join collides when an identity happens to contain
// the delimiter.  Nothing in the token table forbids that — addAuthToken checks
// only token length — so the key encoding has to be injective on its own.
func TestHistoryKeyIsInjectiveOverDelimiter(t *testing.T) {
	a := withSessionID(withIdentity(context.Background(), "alice|b"), "")
	b := withSessionID(withIdentity(context.Background(), "alice"), "b")

	if historyKey(a) == historyKey(b) {
		t.Fatalf("identity %q + session %q collides with identity %q + session %q: both key to %q",
			"alice|b", "", "alice", "b", historyKey(a))
	}
}

func TestHistoryIsolatedPerCaller(t *testing.T) {
	s := &Server{history: newFetchHistoryCache(nil)}

	alice := withSessionID(withIdentity(context.Background(), "alice"), "S1")
	bob := withSessionID(withIdentity(context.Background(), "bob"), "S1")

	s.recordFetch(alice, fetchRecord{URL: "https://alice.example/1", Outcome: "ok", Read: readDepthFull})
	s.recordFetch(bob, fetchRecord{URL: "https://bob.example/1", Outcome: "ok", Read: readDepthFull})

	got, _, _ := s.historyFor(alice).list()
	if len(got) != 1 || got[0].URL != "https://alice.example/1" {
		t.Fatalf("alice sees %+v, want only her own fetch", got)
	}
}

func TestRecordFetchNoOpWithoutHistoryCache(t *testing.T) {
	// A Server built directly in a test leaves history nil; recording must
	// not panic there.
	s := &Server{}
	s.recordFetch(context.Background(), fetchRecord{URL: "https://example.com/"})
	if h := s.historyFor(context.Background()); h != nil {
		t.Error("expected nil history when the cache is disabled")
	}
}

// ── stateless conversation correlation ────────────────────────────────────────

// The regression this exists to catch: go-sdk v1.7.0 stopped reading
// Mcp-Session-Id in stateless mode, so req.Session.ID() is empty for every
// request and the conversation half of the history key vanished.  Two agents
// sharing one token would then share one ledger — evicting each other's
// sources and reading each other's URLs back.
func TestStatelessConversationsKeepSeparateHistories(t *testing.T) {
	s := &Server{history: newFetchHistoryCache(nil)}
	s.config.Stateless = true

	// What the middleware produces: identity from the token, conversation ID
	// from the validated header, no SDK-issued session ID at all.
	convA := withClientSessionID(withIdentity(context.Background(), "alice"), "CONV-A")
	convB := withClientSessionID(withIdentity(context.Background(), "alice"), "CONV-B")

	// sessionIDOf is what the tool handlers call; a nil request stands in for
	// the stateless case where the SDK has no session ID to offer.
	ctxA := withSessionID(convA, sessionIDOf(convA, nil))
	ctxB := withSessionID(convB, sessionIDOf(convB, nil))

	s.recordFetch(ctxA, fetchRecord{URL: "https://example.com/a", Outcome: "ok", Read: readDepthFull})
	s.recordFetch(ctxB, fetchRecord{URL: "https://example.com/b", Outcome: "ok", Read: readDepthFull})

	gotA, _, _ := s.historyFor(ctxA).list()
	gotB, _, _ := s.historyFor(ctxB).list()
	if len(gotA) != 1 || gotA[0].URL != "https://example.com/a" {
		t.Errorf("conversation A sees %+v, want only its own fetch", gotA)
	}
	if len(gotB) != 1 || gotB[0].URL != "https://example.com/b" {
		t.Errorf("conversation B sees %+v, want only its own fetch", gotB)
	}
}

// The same header value is the same conversation: a client that keeps sending
// its ID must keep its ledger across calls.
func TestStatelessSameConversationSharesOneHistory(t *testing.T) {
	s := &Server{history: newFetchHistoryCache(nil)}
	s.config.Stateless = true

	ctx := withClientSessionID(withIdentity(context.Background(), "alice"), "CONV-A")
	ctx = withSessionID(ctx, sessionIDOf(ctx, nil))

	s.recordFetch(ctx, fetchRecord{URL: "https://example.com/1", Outcome: "ok", Read: readDepthFull})
	s.recordFetch(ctx, fetchRecord{URL: "https://example.com/2", Outcome: "ok", Read: readDepthFull})

	if got, _, _ := s.historyFor(ctx).list(); len(got) != 2 {
		t.Errorf("retained %d sources across two calls in one conversation, want 2", len(got))
	}
}

// An SDK-issued session ID always wins.  The fallback exists for the case
// where there is none; letting it override a real one would mean a client
// could pick which ledger it reads by setting a header.
func TestSDKSessionIDBeatsTheClientAssertedOne(t *testing.T) {
	ctx := withClientSessionID(context.Background(), "CLIENT-CLAIMED")
	if got := sessionIDOf(ctx, nil); got != "CLIENT-CLAIMED" {
		t.Fatalf("with no SDK session the fallback should apply, got %q", got)
	}
	// A stateful request carries a real session; the middleware never
	// attaches a client-asserted ID in that mode, so the context is bare and
	// the fallback yields nothing to override with.
	if got := sessionIDOf(context.Background(), nil); got != "" {
		t.Errorf("bare context gave %q, want empty", got)
	}
}

// The documented "true sessionless" configuration — stateful mode with
// GetSessionID returning "" — is an operator asking for no session IDs in
// their logs.  The middleware must not hand them back client-supplied ones.
func TestStatefulModeNeverAttachesClientSessionID(t *testing.T) {
	s := &Server{}
	s.config.Stateless = false

	var seen string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = clientSessionIDFromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(sessionIDHeader, "CLIENT-CLAIMED")
	s.trackClientSession(next).ServeHTTP(httptest.NewRecorder(), req)

	if seen != "" {
		t.Errorf("stateful mode carried a client-asserted session ID %q", seen)
	}
}

func TestTrackClientSessionValidatesTheHeader(t *testing.T) {
	s := &Server{}
	s.config.Stateless = true

	for _, tc := range []struct {
		name, header, want string
	}{
		{"sdk-shaped", "O3GD67SQIYXDYN57XCVQMZYKDI", "O3GD67SQIYXDYN57XCVQMZYKDI"},
		{"absent", "", ""},
		{"newline", "abc\ndef", ""},
		{"tab", "abc\tdef", ""},
		{"space", "abc def", ""},
		{"non-ascii", "abc\u00e9", ""},
		// Rejected outright rather than truncated: truncation would map two
		// distinct conversations onto one key, silently.
		{"over-long", strings.Repeat("a", maxClientSessionIDLen+1), ""},
		{"at-limit", strings.Repeat("a", maxClientSessionIDLen), strings.Repeat("a", maxClientSessionIDLen)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen string
			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = clientSessionIDFromContext(r.Context())
			})
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tc.header != "" {
				req.Header.Set(sessionIDHeader, tc.header)
			}
			s.trackClientSession(next).ServeHTTP(httptest.NewRecorder(), req)
			if seen != tc.want {
				t.Errorf("header %q carried %q, want %q", tc.header, seen, tc.want)
			}
		})
	}
}

// A caller rotating its conversation ID mints unlimited cache keys and pushes
// other callers out.  That is a restoration of the pre-v1.7.0 exposure rather
// than a new one, and it degrades a convenience rather than leaking anything —
// but it has to be visible, because from inside a response an evicted caller
// is indistinguishable from one that never fetched.
func TestHistoryCacheCountsEvictedCallers(t *testing.T) {
	var evicted atomic.Int64
	s := &Server{history: newFetchHistoryCache(func() { evicted.Add(1) })}
	s.config.Stateless = true

	for i := 0; i < fetchHistoryCallers+5; i++ {
		ctx := withClientSessionID(withIdentity(context.Background(), "alice"), fmt.Sprintf("CONV-%d", i))
		ctx = withSessionID(ctx, sessionIDOf(ctx, nil))
		s.recordFetch(ctx, fetchRecord{URL: "https://example.com/x", Outcome: "ok", Read: readDepthFull})
	}

	if got := evicted.Load(); got != 5 {
		t.Errorf("evicted callers = %d, want 5", got)
	}
}

// Tables grow into their cap rather than being allocated at full size: with a
// client-asserted key there can be up to fetchHistoryCallers of them, and
// eager allocation would make idle callers cost the full MCP_HISTORY_ENTRIES.
func TestHistoryTableGrowsLazily(t *testing.T) {
	h := newFetchHistory(5000)
	h.appendRecord(fetchRecord{URL: "https://example.com/1"})
	h.appendRecord(fetchRecord{URL: "https://example.com/2"})

	h.mu.Lock()
	held := len(h.entries)
	h.mu.Unlock()
	if held != 2 {
		t.Errorf("table holds %d records after 2 fetches, want 2 — allocation is not lazy", held)
	}
	if got, _, _ := h.list(); len(got) != 2 {
		t.Errorf("list returned %d, want 2", len(got))
	}
}

// ── tool output ───────────────────────────────────────────────────────────────

// newSourcesTestServer builds a Server with both halves the sources tool
// needs: a history cache and a fence signing key.
//
// The key is not optional.  wrapFence* signs unconditionally, and
// ed25519.Sign panics rather than erroring on a nil private key, so a Server
// literal that omits fenceSigningKey fails inside crypto/ed25519 with an
// index-out-of-range that says nothing about the missing field.
func newSourcesTestServer(t *testing.T) *Server {
	t.Helper()
	s := newTestFenceServer(t)
	s.history = newFetchHistoryCache(nil)
	return s
}

// sourcesTestCtx builds the context a tool handler actually operates under.
//
// Every handler opens with ctx = withSessionID(ctx, sessionIDOf(req)), and
// these tests pass a nil request, so that call resolves the session ID to "".
// Seeding a different one here would key recordFetch and the tool's own
// lookup to two separate histories and the tool would correctly report an
// empty list — an artifact of the nil request, not a defect in the keying.
// Production cannot hit it: every handler derives the ID from the same
// request in the same way.
//
// Identity is what these tests actually vary, and it is unaffected.
func sourcesTestCtx(identity string) context.Context {
	return withSessionID(withIdentity(context.Background(), identity), "")
}

// textOf pulls the single text block out of a tool result.
func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) != 1 {
		t.Fatalf("expected exactly one content block, got %+v", res)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected a text block, got %T", res.Content[0])
	}
	return tc.Text
}

func decodeSourcesPayload(t *testing.T, fenced string) sourcesPayload {
	t.Helper()
	const open, close = "<![CDATA[", "]]>"
	i := strings.Index(fenced, open)
	j := strings.LastIndex(fenced, close)
	if i < 0 || j < 0 || j <= i {
		t.Fatalf("no CDATA section in fenced output:\n%s", fenced)
	}
	var p sourcesPayload
	if err := json.Unmarshal([]byte(fenced[i+len(open):j]), &p); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	return p
}

func TestSessionSourcesDeduplicatesAndCountsRepeats(t *testing.T) {
	s := newSourcesTestServer(t)
	ctx := sourcesTestCtx("alice")

	s.recordFetch(ctx, fetchRecord{Tool: "searxng_url_metadata", URL: "https://example.com/a", Outcome: "ok", Read: readDepthMetadata})
	s.recordFetch(ctx, fetchRecord{Tool: "searxng_read_url", URL: "https://example.com/a", Outcome: "ok", Read: readDepthFull})
	s.recordFetch(ctx, fetchRecord{Tool: "searxng_read_url", URL: "https://example.com/b", Outcome: "error", Read: readDepthNone, Err: "URL returned HTTP 404"})

	res, _, err := s.toolSessionSources(ctx, nil, sessionSourcesInput{})
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}
	p := decodeSourcesPayload(t, textOf(t, res))

	if p.Total != 3 {
		t.Errorf("total_fetches = %d, want 3", p.Total)
	}
	if len(p.Sources) != 2 {
		t.Fatalf("sources = %d, want 2 (a deduplicated, b)", len(p.Sources))
	}
	// Newest first, and the deepest read for a URL wins the row — so /a
	// reports read=full, not the earlier metadata-only call.
	if p.Sources[0].URL != "https://example.com/b" {
		t.Errorf("first = %q, want .../b", p.Sources[0].URL)
	}
	if p.Sources[1].URL != "https://example.com/a" || p.Sources[1].Read != string(readDepthFull) {
		t.Errorf("second = %+v, want .../a read=full", p.Sources[1])
	}
	if p.Sources[1].Fetches != 2 {
		t.Errorf("fetches = %d, want 2", p.Sources[1].Fetches)
	}
	// A failed fetch must be present and marked, not omitted.
	if p.Sources[0].Outcome != "error" || p.Sources[0].Error == "" {
		t.Errorf("failed fetch not surfaced: %+v", p.Sources[0])
	}
}

func TestSessionSourcesSinceSeq(t *testing.T) {
	s := newSourcesTestServer(t)
	ctx := sourcesTestCtx("alice")

	for _, u := range []string{"https://example.com/1", "https://example.com/2", "https://example.com/3"} {
		s.recordFetch(ctx, fetchRecord{Tool: "searxng_read_url", URL: u, Outcome: "ok", Read: readDepthFull})
	}

	res, _, err := s.toolSessionSources(ctx, nil, sessionSourcesInput{SinceSeq: 2})
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}
	p := decodeSourcesPayload(t, textOf(t, res))

	if len(p.Sources) != 1 {
		t.Fatalf("since_seq=2 returned %d sources, want 1: %+v", len(p.Sources), p.Sources)
	}
	if p.Sources[0].Seq != 3 {
		t.Fatalf("since_seq=2 returned seq %d, want 3", p.Sources[0].Seq)
	}
}

// elided answers "is this list still complete?", so it counts sources dropped
// to make room and nothing else.  Deriving it as total-minus-rows, as the
// payload once did, made a caller who re-read ten URLs five times each look
// like one who had lost forty sources.
func TestSessionSourcesElidedCountsDroppedSourcesNotRepeats(t *testing.T) {
	s := newSourcesTestServer(t)
	ctx := sourcesTestCtx("alice")

	for i := 0; i < 10; i++ {
		u := fmt.Sprintf("https://example.com/%d", i)
		for r := 0; r < 5; r++ {
			s.recordFetch(ctx, fetchRecord{Tool: "searxng_read_url", URL: u, Outcome: "ok", Read: readDepthFull})
		}
	}

	res, _, err := s.toolSessionSources(ctx, nil, sessionSourcesInput{})
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}
	p := decodeSourcesPayload(t, textOf(t, res))

	if p.Elided != 0 {
		t.Errorf("elided = %d, want 0 — 50 fetches of 10 URLs drop nothing", p.Elided)
	}
	if p.Total != 50 {
		t.Errorf("total_fetches = %d, want 50", p.Total)
	}
	if len(p.Sources) != 10 || p.Returned != 10 {
		t.Fatalf("sources = %d (returned %d), want 10", len(p.Sources), p.Returned)
	}
	if p.Sources[0].Fetches != 5 {
		t.Errorf("fetches = %d, want 5", p.Sources[0].Fetches)
	}
}

// A source read again after a previous call is new information — the caller
// went back to it — and since_seq is how the model asks what has changed.
func TestSessionSourcesSinceSeqSurfacesARefetchedSource(t *testing.T) {
	s := newSourcesTestServer(t)
	ctx := sourcesTestCtx("alice")

	s.recordFetch(ctx, fetchRecord{Tool: "searxng_read_url", URL: "https://example.com/1", Outcome: "ok", Read: readDepthMetadata})
	s.recordFetch(ctx, fetchRecord{Tool: "searxng_read_url", URL: "https://example.com/2", Outcome: "ok", Read: readDepthFull})
	s.recordFetch(ctx, fetchRecord{Tool: "searxng_read_url", URL: "https://example.com/1", Outcome: "ok", Read: readDepthFull})

	res, _, err := s.toolSessionSources(ctx, nil, sessionSourcesInput{SinceSeq: 2})
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}
	p := decodeSourcesPayload(t, textOf(t, res))

	if len(p.Sources) != 1 {
		t.Fatalf("since_seq=2 returned %d sources, want 1: %+v", len(p.Sources), p.Sources)
	}
	if p.Sources[0].URL != "https://example.com/1" || p.Sources[0].Seq != 3 {
		t.Errorf("got %q at seq %d, want .../1 at seq 3", p.Sources[0].URL, p.Sources[0].Seq)
	}
	if p.Sources[0].Read != string(readDepthFull) {
		t.Errorf("read = %q, want full", p.Sources[0].Read)
	}
}

// The counter that answers "is the cap big enough?".  A list that came back
// short means an agent composed its answer against a record that no longer
// held everything it had read — which is the condition worth alerting on, and
// which nothing in the response itself makes visible to an operator.
func TestSessionSourcesElidedMetricCountsShortLists(t *testing.T) {
	s := newSourcesTestServer(t)
	s.config.HistoryEntries = 2
	ctx := sourcesTestCtx("alice")

	s.recordFetch(ctx, fetchRecord{Tool: "searxng_read_url", URL: "https://example.com/1", Outcome: "ok", Read: readDepthFull})
	s.recordFetch(ctx, fetchRecord{Tool: "searxng_read_url", URL: "https://example.com/2", Outcome: "ok", Read: readDepthFull})

	res, _, err := s.toolSessionSources(ctx, nil, sessionSourcesInput{})
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}
	if p := decodeSourcesPayload(t, textOf(t, res)); p.Elided != 0 {
		t.Errorf("elided = %d, want 0 — the list is still complete", p.Elided)
	}
	if n := s.metrics.SourcesElided.Load(); n != 0 {
		t.Errorf("mcp_session_sources_elided_total = %d, want 0", n)
	}

	// One source past the cap: the list is now short, and stays short.
	s.recordFetch(ctx, fetchRecord{Tool: "searxng_read_url", URL: "https://example.com/3", Outcome: "ok", Read: readDepthFull})

	res, _, err = s.toolSessionSources(ctx, nil, sessionSourcesInput{})
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}
	p := decodeSourcesPayload(t, textOf(t, res))
	if p.Elided != 1 {
		t.Errorf("elided = %d, want 1", p.Elided)
	}
	if p.Total != 3 || len(p.Sources) != 2 {
		t.Errorf("total_fetches/sources = %d/%d, want 3/2", p.Total, len(p.Sources))
	}
	if n := s.metrics.SourcesElided.Load(); n != 1 {
		t.Errorf("mcp_session_sources_elided_total = %d, want 1", n)
	}
}

func TestSessionSourcesEmptyHistory(t *testing.T) {
	s := newSourcesTestServer(t)
	ctx := sourcesTestCtx("alice")

	res, _, err := s.toolSessionSources(ctx, nil, sessionSourcesInput{})
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}
	p := decodeSourcesPayload(t, textOf(t, res))
	if len(p.Sources) != 0 || p.Total != 0 {
		t.Errorf("empty history returned %+v", p)
	}
	if p.Note == "" {
		t.Error("note must be present even when the list is empty — it is what tells the model the absence is authoritative")
	}
}

func TestSessionSourcesPrefersFinalURL(t *testing.T) {
	s := newSourcesTestServer(t)
	ctx := sourcesTestCtx("alice")

	s.recordFetch(ctx, fetchRecord{
		Tool:     "searxng_read_url",
		URL:      "https://example.com/short",
		FinalURL: "https://www.example.com/full/article?id=7",
		Outcome:  "ok",
		Read:     readDepthFull,
	})

	res, _, err := s.toolSessionSources(ctx, nil, sessionSourcesInput{})
	if err != nil {
		t.Fatalf("tool returned error: %v", err)
	}
	p := decodeSourcesPayload(t, textOf(t, res))
	if len(p.Sources) != 1 {
		t.Fatalf("sources = %d, want 1", len(p.Sources))
	}

	if p.Sources[0].URL != "https://www.example.com/full/article?id=7" {
		t.Errorf("url = %q, want the post-redirect URL", p.Sources[0].URL)
	}
	if p.Sources[0].RequestedURL != "https://example.com/short" {
		t.Errorf("requested_url = %q, want the pre-redirect URL", p.Sources[0].RequestedURL)
	}
}

// ── CDATA fence ───────────────────────────────────────────────────────────────

func TestCDATAFencePreservesAmpersandsInURLs(t *testing.T) {
	// The regression this exists to prevent: the escaped fence turns "&"
	// into "&amp;", and a model echoing the escaped form back produces a
	// URL that does not resolve.  Query-dense retail URLs hit this on
	// essentially every entry.
	s := newTestFenceServer(t)
	raw := `https://geizhals.de/?cat=gehps&sort=p&xf=1_flex+atx`

	out, err := s.wrapFenceCDATA(raw, FenceTypeData, FenceUntrusted, "test")
	if err != nil {
		t.Fatalf("wrapFenceCDATA: %v", err)
	}
	if !strings.Contains(out, raw) {
		t.Errorf("URL was altered in the CDATA body:\n%s", out)
	}
	if strings.Contains(out, "&amp;") {
		t.Errorf("entity escaping leaked into the CDATA path:\n%s", out)
	}
	if !strings.Contains(out, `encoding="cdata"`) {
		t.Error("encoding attribute missing — a verifier cannot tell how to recover the signed bytes")
	}
}

// The property that matters is not the shape of the escape but that the fence
// is well-formed XML and the content comes back byte-identical.  Counting "]]>"
// occurrences tested cdataEscape's implementation; parsing tests the contract.
//
// Note the escape yields "]]]]>" for a single "]]>": two literal brackets, then
// the sequence that closes the section.  Reading that as two terminators is an
// easy miscount, and exactly why this asserts on a parse instead.
func TestCDATAFenceRoundTripsThroughXMLParser(t *testing.T) {
	s := newTestFenceServer(t)

	for _, raw := range []string{
		`https://geizhals.de/?cat=gehps&sort=p&xf=1_flex+atx`,
		`a]]>b`,
		`]]>`,
		`]]>]]>`,
		`a <![CDATA[ b`,
		`{"url":"https://x.example/?a=1&b=2","t":"<script>"}`,
	} {
		out, err := s.wrapFenceCDATA(raw, FenceTypeData, FenceUntrusted, "test")
		if err != nil {
			t.Fatalf("wrapFenceCDATA(%q): %v", raw, err)
		}

		// Skip the awareness preamble.  It cannot be found by searching for
		// "<sec:fence": the preamble quotes both that tag and its closing
		// form while explaining the boundary rules, so the first match lands
		// in prose and a parser started there runs off the end of the
		// document.  The namespace declaration appears only on the real
		// element, which is what makes it a usable anchor — and the reason
		// the fence identifies its true boundary by nonce rather than by tag
		// name in the first place.
		i := strings.Index(out, `<sec:fence xmlns:sec=`)
		if i < 0 {
			t.Fatalf("no namespaced <sec:fence element in output for %q", raw)
		}

		var got strings.Builder
		dec := xml.NewDecoder(strings.NewReader(out[i:]))
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("fence is not well-formed XML for %q: %v\n%s", raw, err, out[i:])
			}
			if cd, ok := tok.(xml.CharData); ok {
				got.WriteString(string(cd))
			}
		}

		if strings.TrimSpace(got.String()) != raw {
			t.Errorf("round trip altered content\n got: %q\nwant: %q", strings.TrimSpace(got.String()), raw)
		}
	}
}

func TestEscapedFenceCanonicalFormUnchanged(t *testing.T) {
	// Adding the encoding attribute must not alter the canonical bytes of
	// an ordinary fence, or every signature over previously-emitted fences
	// becomes unverifiable.
	meta := fenceMetadata{
		Type:      FenceTypeContent,
		Rating:    FenceUntrusted,
		Source:    "https://example.com/",
		Timestamp: time.Unix(0, 0),
		Nonce:     "00112233445566778899aabbccddeeff",
		KeyID:     "0123456789abcdef",
		Version:   fenceFormatVersion,
	}
	if strings.Contains(meta.canonicalAttributes(), "encoding=") {
		t.Error("encoding must be absent from the canonical form when unset")
	}

	meta.Encoding = fenceEncodingCDATA
	if !strings.Contains(meta.canonicalAttributes(), `encoding="cdata"`) {
		t.Error("encoding must be inside the canonical form when set, or an attacker could flip it freely")
	}
}
