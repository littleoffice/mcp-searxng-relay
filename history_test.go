package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── ring buffer ───────────────────────────────────────────────────────────────

func TestFetchHistoryOrderingIsNewestFirst(t *testing.T) {
	h := &fetchHistory{}
	for i := 1; i <= 3; i++ {
		h.appendRecord(fetchRecord{URL: "https://example.com/" + string(rune('a'+i-1))})
	}

	got, total := h.list()
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
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

func TestFetchHistoryWrapsAndReportsTrueTotal(t *testing.T) {
	h := &fetchHistory{}
	const n = fetchHistoryEntries + 17
	for i := 1; i <= n; i++ {
		h.appendRecord(fetchRecord{CharsRead: i})
	}

	got, total := h.list()
	if total != n {
		t.Errorf("total = %d, want %d — the count of everything ever appended, not what was retained", total, n)
	}
	if len(got) != fetchHistoryEntries {
		t.Fatalf("retained = %d, want %d", len(got), fetchHistoryEntries)
	}
	if got[0].CharsRead != n {
		t.Errorf("newest = %d, want %d", got[0].CharsRead, n)
	}
	if want := n - fetchHistoryEntries + 1; got[len(got)-1].CharsRead != want {
		t.Errorf("oldest retained = %d, want %d", got[len(got)-1].CharsRead, want)
	}
	// Sequence numbers must keep climbing past the ring size, otherwise
	// since_seq would silently re-serve entries after a wrap.
	if got[0].Seq != n {
		t.Errorf("newest seq = %d, want %d", got[0].Seq, n)
	}
}

func TestFetchHistoryConcurrentAppend(t *testing.T) {
	// The LRU protects its map, not the ring behind the returned pointer.
	// Run with -race.
	h := &fetchHistory{}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.appendRecord(fetchRecord{URL: "https://example.com/x"})
			_, _ = h.list()
		}()
	}
	wg.Wait()

	if _, total := h.list(); total != 64 {
		t.Errorf("total = %d, want 64 — lost or double-counted appends", total)
	}
}

// ── caller keying ─────────────────────────────────────────────────────────────

func TestHistoryKeySeparatesCallersSharingASessionID(t *testing.T) {
	// The case this guards: MCP_STATELESS, or the documented configuration
	// where GetSessionID returns "".  Keying on session alone would collapse
	// every caller onto one history and hand one tenant another's URLs.
	a := withSessionID(withIdentity(context.Background(), "alice"), "")
	b := withSessionID(withIdentity(context.Background(), "bob"), "")

	if historyKey(a) == historyKey(b) {
		t.Fatal("distinct identities with empty session IDs share a history key")
	}
}

func TestHistoryIsolatedPerCaller(t *testing.T) {
	s := &Server{history: newFetchHistoryCache()}

	alice := withSessionID(withIdentity(context.Background(), "alice"), "S1")
	bob := withSessionID(withIdentity(context.Background(), "bob"), "S1")

	s.recordFetch(alice, fetchRecord{URL: "https://alice.example/1", Outcome: "ok", Read: readDepthFull})
	s.recordFetch(bob, fetchRecord{URL: "https://bob.example/1", Outcome: "ok", Read: readDepthFull})

	got, _ := s.historyFor(alice).list()
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
	s.history = newFetchHistoryCache()
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
	// Newest first, and the newest record for a URL wins the row — so /a
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

func TestCDATAFenceSplitsTerminator(t *testing.T) {
	s := newTestFenceServer(t)
	out, err := s.wrapFenceCDATA(`a]]>b`, FenceTypeData, FenceUntrusted, "test")
	if err != nil {
		t.Fatalf("wrapFenceCDATA: %v", err)
	}
	// The body must not contain a bare terminator that would end the
	// section early and spill the remainder into the document.
	body := out[strings.Index(out, "<![CDATA["):]
	if strings.Count(body, "]]>") != 3 {
		t.Errorf("expected the split form (]]]]><![CDATA[> plus the real terminator), got:\n%s", body)
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
