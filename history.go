package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── Per-caller fetch history ──────────────────────────────────────────────────
//
// Why this exists.  The observed failure mode is not that the model cannot
// *reach* a URL, it is that the model reproduces one incorrectly — or invents
// one outright — in the final answer it writes after the last tool call.  That
// answer is composed thousands of tokens after the search results scrolled
// past, and no MCP server ever sees it, so nothing on the wire can validate it.
//
// The mitigation available to a server is to make the correct bytes cheap to
// re-read immediately before the answer is written.  searxng_session_sources
// returns the exact URLs this relay fetched for this caller, so the model
// checks a list instead of recalling one.  The same list distinguishes "read
// in full" from "metadata only" from "the fetch failed", which is the
// distinction an instruction like "don't cite links you haven't read" is
// actually asking about and which the model cannot reliably introspect.
//
// Storage shape.  One LRU keyed per caller, whose *value* is that caller's
// entire history in a fixed-size table of sources.  The obvious alternative — one flat LRU
// with a synthetic "caller:seq" key — is wrong twice over: eviction becomes
// global (one busy agent flushes every other caller's history) and answering
// "what did this caller fetch?" requires walking the whole keyspace.  Here,
// eviction means "this caller went quiet", which is the intended semantic, and
// a lookup is O(1).
//
// Lifetime.  In-process only, and deliberately so.  The history needs to
// outlive the conversation and nothing more; a restart ends the conversation
// anyway.  Shared storage (Redis et al.) would extend the scope to "everything
// this identity ever fetched, across all conversations", which makes the list
// *worse* for its purpose — the model cannot tell which entries belong to the
// exchange it is currently in.  Cross-replica continuity is a routing concern
// and belongs to session affinity at the ingress, not to a datastore here.

const (
	// fetchHistoryEntries is the default number of distinct sources one
	// caller retains, overridable per deployment with MCP_HISTORY_ENTRIES.
	// Repeat fetches of a URL already held — a metadata triage followed by
	// a read, a paginated document, a re-read — fold into the entry that is
	// there and cost no slot, so this is a count of sources and not of tool
	// calls.  The list is read into the context window on every call, so it
	// is a token budget as much as a memory one: 50 sources is far more than
	// a single research task produces and still costs well under a page of
	// context.  Sources dropped to make room are reported as a count rather
	// than vanishing silently.
	//
	// Raise it for agents whose tasks legitimately visit more sources than
	// that; the ceiling on doing so is the context the list occupies on
	// every call, not memory — see MCP_HISTORY_ENTRIES in config.go.
	fetchHistoryEntries = 50

	// fetchHistoryCallers bounds how many distinct callers we retain
	// histories for.  Matched to maxSessions so the history cache cannot
	// outgrow the session cap that already bounds this process.  Worst
	// case is ~1000 × MCP_HISTORY_ENTRIES small records, which at the
	// default is negligible next to the content cache (CACHE_MAX_ENTRIES ×
	// MAX_EXTRACTED_CHARS).
	fetchHistoryCallers = maxSessions
)

// readDepth records how much of a URL was actually read, which is a finer
// distinction than "was it fetched".  A metadata-only call and a first-page
// read both look like a fetch in the logs; only one of them justifies a claim
// to have read the source.
type readDepth string

const (
	readDepthNone     readDepth = "none"     // fetch failed; nothing was read
	readDepthMetadata readDepth = "metadata" // searxng_url_metadata: no body
	readDepthPartial  readDepth = "partial"  // one window of a longer document
	readDepthFull     readDepth = "full"     // the whole extracted text
	readDepthImage    readDepth = "image"    // image bytes; no text to read
)

// fetchRecord is one entry in a caller's history.
//
// URL is stored exactly as the fetch pipeline used it, and FinalURL exactly as
// the transport reported it after redirects.  Neither is normalised for
// display: the entire value of this record is that it is byte-identical to
// what was fetched.
type fetchRecord struct {
	Seq        int
	Tool       string
	URL        string
	FinalURL   string
	Title      string
	FetchedAt  time.Time
	Outcome    string // "ok" or "error"
	Err        string
	Read       readDepth
	CharsRead  int
	TotalChars int
	FromCache  bool
	Fetches    int // fetches folded into this entry, including the first
}

// fetchHistory is one caller's table of retained sources.
//
// A slot holds one *source*, not one fetch: a repeat fetch of a URL already
// held folds into the entry that is there (see mergeRecord) rather than
// consuming a slot.  Slot-per-fetch is the obvious shape and the wrong one,
// because the things that repeat are exactly the things a research task does
// most — triaging a URL with metadata before reading it, paging through a long
// document one window at a time, re-reading after a cache hit.  Under
// slot-per-fetch a single six-window read costs six of the fifty, and sources
// the caller genuinely cited can fall out of the table while the same URL
// occupies it six times over.  Deduplicating at read time, which is what this
// once did, is too late to help: by then the evicted sources are gone.
//
// index maps a source's citable URL to its slot, which makes the fold O(1).
// It is maintained in step with entries on every write, and an entry's citable
// URL must never change without its index key changing with it.
//
// entries grows one slot at a time up to cap, rather than being allocated at
// full size on creation.  The difference matters because how many of these
// exist is not entirely up to us: in stateless mode the conversation half of
// the cache key is client-asserted, so a caller rotating it can create up to
// fetchHistoryCallers tables.  Eager allocation would make that cost
// MCP_HISTORY_ENTRIES × 1,000 records of resident memory regardless of how
// little was ever recorded in them — fine at the default 50, roughly 880 MB if
// an operator raised the cap to 5,000.  Growing on demand makes the cost track
// what callers actually fetched.
//
// The zero value of this struct is usable and takes the default cap on first
// write, which keeps a directly-constructed fetchHistory (tests, and any
// future caller with no config to hand) from being a zero-cap table that drops
// everything written to it.
//
// The mutex is not redundant with the LRU's own locking.  The cache returns a
// *fetchHistory, and two concurrent requests from the same caller then write
// through the same pointer; the cache's lock protects its map, not the value
// behind the pointer.
type fetchHistory struct {
	mu      sync.Mutex
	entries []fetchRecord  // grows to cap; len(entries) is what is in use
	cap     int            // sources retained before eviction starts
	index   map[string]int // citable URL -> slot in entries
	total   int            // fetches ever appended; source of Seq
	evicted int            // distinct sources dropped to make room
}

// newFetchHistory returns a history retaining n sources, falling back to the
// default for a non-positive n so a misconfigured cap cannot produce a table
// that drops everything written to it.
func newFetchHistory(n int) *fetchHistory {
	if n <= 0 {
		n = fetchHistoryEntries
	}
	return &fetchHistory{cap: n}
}

// citableURL is the URL an entry is filed and cited under: where the fetch
// ended up, or where it was aimed when it never got there.  It is both the
// index key and the url field the model copies, and those two must be the same
// string — an entry filed under one and reported under another is unreachable
// for eviction and mismatched for since_seq.
func citableURL(r fetchRecord) string {
	if r.FinalURL != "" {
		return r.FinalURL
	}
	return r.URL
}

// depthRank orders read depths by how much of a document each one entitles the
// caller to claim.  metadata and image rank together: both mean "the fetch
// worked and no text came back".
func depthRank(d readDepth) int {
	switch d {
	case readDepthFull:
		return 4
	case readDepthPartial:
		return 3
	case readDepthMetadata, readDepthImage:
		return 2
	default: // readDepthNone, or a record that never set the field
		return 1
	}
}

// mergeRecord folds a repeat fetch into the entry already held for that URL.
//
// The merged entry answers two questions whose answers can differ, so it takes
// each group of fields from the record that actually knows:
//
//   - "how much of this did we ever manage to read?" — Read, Outcome, Err,
//     Title, CharsRead and TotalChars come from the deepest read achieved.  A
//     later metadata-only triage does not un-read a page already read in full,
//     and a re-fetch that 404s does not erase the copy that was returned.
//     Taking the newest record wholesale, as the old read-time dedup did,
//     understated exactly the claim this tool exists to support.
//   - "when was it last touched, and how?" — Seq, FetchedAt, Tool and
//     FromCache come from the current fetch, which is what since_seq and the
//     newest-first ordering are asking about.
//
// Equal depths resolve to the newer record: the same claim, more recently
// worded.
func mergeRecord(held, cur fetchRecord) fetchRecord {
	best, other := cur, held
	if depthRank(held.Read) > depthRank(cur.Read) {
		best, other = held, cur
	}

	merged := best
	// The URL pair comes from cur unconditionally: it determines the entry's
	// citable URL, which is the key this record is indexed under.
	merged.URL, merged.FinalURL = cur.URL, cur.FinalURL
	merged.Seq, merged.FetchedAt = cur.Seq, cur.FetchedAt
	merged.Tool, merged.FromCache = cur.Tool, cur.FromCache
	merged.Fetches = held.Fetches + 1

	// Character counts are a high-water mark rather than the winning
	// record's own, so a re-read that returned less does not shrink what we
	// report having held.
	if other.CharsRead > merged.CharsRead {
		merged.CharsRead = other.CharsRead
	}
	if other.TotalChars > merged.TotalChars {
		merged.TotalChars = other.TotalChars
	}
	if merged.Title == "" {
		merged.Title = other.Title
	}
	return merged
}

// appendRecord files r, assigning it the next sequence number, and returns the
// assigned Seq along with whether filing it dropped another source to make
// room.  A fetch of a URL already held updates that entry in place; the Seq is
// still consumed, so total keeps counting fetches.
//
// The eviction flag is reported rather than counted here because the metric it
// feeds lives on the Server, and a fetchHistory deliberately knows nothing
// about one.
//
// Sequence numbers are monotonic per caller and are what the model uses to
// order the list.  A timestamp answers "how stale is this"; a sequence number
// answers "what did I do most recently", and only the second is needed to pick
// the right URL out of a list.  Both are carried because they are different
// questions — a cache hit at seq 47 can legitimately hold bytes retrieved at
// seq 3.
func (h *fetchHistory) appendRecord(r fetchRecord) (seq int, evicted bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.total++
	r.Seq = h.total
	r.Fetches = 1

	if h.cap <= 0 {
		h.cap = fetchHistoryEntries
	}
	if h.index == nil {
		h.index = make(map[string]int)
	}
	key := citableURL(r)
	if idx, ok := h.index[key]; ok {
		h.entries[idx] = mergeRecord(h.entries[idx], r)
		return r.Seq, false
	}

	if len(h.entries) < h.cap {
		h.entries = append(h.entries, r)
		h.index[key] = len(h.entries) - 1
		return r.Seq, false
	}

	idx := h.evictLeastRecent()
	h.entries[idx] = r
	h.index[key] = idx
	return r.Seq, true
}

// evictLeastRecent frees the slot whose source was touched longest ago and
// returns it.  Called with h.mu held, and only when the table is at capacity.
//
// Least recently *touched*, not first seen: a merged entry keeps its slot but
// takes a new Seq, so insertion order stops tracking recency the moment a
// caller re-fetches anything, and evicting by slot order would drop the source
// it had just re-read.  The scan is O(len(h.entries)) and runs only on
// overflow.
func (h *fetchHistory) evictLeastRecent() int {
	oldest := 0
	for i := 1; i < len(h.entries); i++ {
		if h.entries[i].Seq < h.entries[oldest].Seq {
			oldest = i
		}
	}
	delete(h.index, citableURL(h.entries[oldest]))
	h.evicted++
	return oldest
}

// list returns the retained sources newest-first, the number of fetches ever
// appended, and the number of distinct sources dropped to make room.
//
// Newest-first is deliberate: it makes recency positional, so the model reads
// the ordering off the list rather than inferring it from sequence arithmetic.
// The ordering comes from Seq rather than from slot order because a merged
// entry keeps its slot and takes a new Seq.
func (h *fetchHistory) list() (records []fetchRecord, total, evicted int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	records = make([]fetchRecord, len(h.entries))
	copy(records, h.entries)
	sort.Slice(records, func(i, j int) bool { return records[i].Seq > records[j].Seq })
	return records, h.total, h.evicted
}

// historyKey derives the cache key for the current caller.
//
// Keying on session ID alone is unsafe here.  Under MCP_STATELESS the session
// half is whatever the client asserted — since go-sdk v1.7.0 the SDK does not
// read Mcp-Session-Id at all in that mode, so the value comes from this
// relay's own transport middleware (see clientSessionCtxKey) and is empty for
// any client that sends no header.  The README documents a further
// configuration in which it is empty for every request.  In all of those
// cases several callers would collapse onto one key and a caller could be
// handed another caller's fetched URLs — a cross-tenant leak in exactly the
// deployments this project is aimed at.
//
// Identity is server-validated in both session modes, so pairing the two keeps
// callers separated even when the session half is empty, forged, or shared.
// That half now does all the tenant-separating work in stateless mode: the
// conversation half only decides how a single tenant's fetches are grouped.
//
// The identity is length-prefixed rather than merely delimited.  Identities are
// arbitrary operator-chosen strings — addAuthToken validates only token length,
// and strings.Cut on the first ":" means a colon cannot appear in one but
// nothing excludes the delimiter used here.  A plain "identity|session" join is
// therefore ambiguous: identity "alice|b" with an empty session ID and identity
// "alice" with session "b" both produce "alice|b", and the two callers share a
// history.  The length prefix makes the encoding injective, which is the same
// reason buildFenceSigningInput length-prefixes its content rather than relying
// on the delimiter being unreachable.
func historyKey(ctx context.Context) string {
	identity := identityFromContext(ctx)
	return strconv.Itoa(len(identity)) + "|" + identity + "|" + sessionIDFromContext(ctx)
}

// historyFor returns the caller's history, creating it on first use.
//
// The get-or-create is guarded by historyMu rather than assembled from LRU
// primitives: without it, two concurrent first fetches from one caller can
// both miss, both construct a history, and one silently overwrite the other,
// losing a record at exactly the moment the caller's history is shortest.
//
// Returns nil when history is disabled (a Server built directly in tests
// leaves the cache nil); every caller tolerates a nil result.
func (s *Server) historyFor(ctx context.Context) *fetchHistory {
	if s.history == nil {
		return nil
	}
	key := historyKey(ctx)

	s.historyMu.Lock()
	defer s.historyMu.Unlock()

	if h, ok := s.history.Get(key); ok {
		return h
	}
	h := newFetchHistory(s.config.HistoryEntries)
	s.history.Add(key, h)
	return h
}

// recordFetch appends one record to the calling session's history.  Called on
// both the success and the failure path of every URL tool: a 404 present in
// the list is more useful to the model than a 404 absent from it, because
// absence is indistinguishable from "never tried".
func (s *Server) recordFetch(ctx context.Context, r fetchRecord) {
	h := s.historyFor(ctx)
	if h == nil {
		return
	}
	if r.FetchedAt.IsZero() {
		r.FetchedAt = time.Now()
	}
	if _, evicted := h.appendRecord(r); evicted {
		s.metrics.HistoryEvictions.Add(1)
	}
}

// ── Tool: session sources ─────────────────────────────────────────────────────

type sessionSourcesInput struct {
	SinceSeq int `json:"since_seq,omitempty" jsonschema:"return only entries with a sequence number greater than this (default: 0, meaning all retained entries). Use the highest seq from a previous call to see only what has been fetched since"`
}

// sourceEntry is the per-URL view returned to the model: one row per distinct
// URL rather than one row per fetch, since a URL fetched three times is one
// source.
type sourceEntry struct {
	URL          string `json:"url"`
	RequestedURL string `json:"requested_url,omitempty"`
	Title        string `json:"title,omitempty"`
	Read         string `json:"read"`
	Outcome      string `json:"outcome"`
	Error        string `json:"error,omitempty"`
	CharsRead    int    `json:"chars_read,omitempty"`
	TotalChars   int    `json:"total_chars,omitempty"`
	FetchedAt    string `json:"fetched_at"`
	FromCache    bool   `json:"from_cache,omitempty"`
	Tool         string `json:"tool"`
	Seq          int    `json:"seq"`
	Fetches      int    `json:"fetches,omitempty"`
}

// sourcesPayload is the whole response.  The three counts describe different
// things and are only useful apart: Total counts fetches (so it exceeds the
// number of rows whenever a URL was fetched more than once), Returned counts
// the rows actually sent after since_seq filtering, and Elided counts distinct
// sources dropped to make room — the one number that says the list is no
// longer complete.
type sourcesPayload struct {
	Note     string        `json:"note"`
	Total    int           `json:"total_fetches"`
	Returned int           `json:"returned"`
	Elided   int           `json:"elided"`
	Sources  []sourceEntry `json:"sources"`
}

// sourcesNote is carried in the payload rather than left to the tool
// description, so the framing travels with the data into the context window
// where the answer is actually composed.
const sourcesNote = "URLs below are byte-exact as fetched by this relay for this caller. " +
	"Copy them verbatim; do not reconstruct them from memory. " +
	"A URL absent from this list was not fetched by this relay, and an entry " +
	"with read=metadata or outcome=error was not read in full."

func (s *Server) toolSessionSources(
	ctx context.Context,
	req *mcp.CallToolRequest,
	in sessionSourcesInput,
) (*mcp.CallToolResult, any, error) {
	ctx = withSessionID(ctx, sessionIDOf(ctx, req))
	lg := callerLogger(ctx)
	s.metrics.SourcesTotal.Add(1)

	h := s.historyFor(ctx)
	var records []fetchRecord
	var total, evicted int
	if h != nil {
		records, total, evicted = h.list()
	}

	// One row per source already: appendRecord folds repeat fetches into the
	// entry they belong to, so records carries no duplicates and there is no
	// second pass to make here.
	entries := make([]sourceEntry, 0, len(records))
	for _, r := range records {
		if r.Seq <= in.SinceSeq {
			continue
		}
		e := sourceEntry{
			URL:        citableURL(r),
			Title:      r.Title,
			Read:       string(r.Read),
			Outcome:    r.Outcome,
			Error:      r.Err,
			CharsRead:  r.CharsRead,
			TotalChars: r.TotalChars,
			FetchedAt:  r.FetchedAt.UTC().Format(time.RFC3339),
			FromCache:  r.FromCache,
			Tool:       r.Tool,
			Seq:        r.Seq,
			Fetches:    r.Fetches,
		}
		// Only surface the requested URL when a redirect moved it; the
		// two being equal is the common case and the extra field would
		// be noise the model has to disambiguate.
		if r.FinalURL != "" && r.FinalURL != r.URL {
			e.RequestedURL = r.URL
		}
		entries = append(entries, e)
	}

	payload := sourcesPayload{
		Note:     sourcesNote,
		Total:    total,
		Returned: len(entries),
		Elided:   evicted,
		Sources:  entries,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal session sources: %w", err)
	}

	// CDATA, not entity escaping.  The whole point of this response is that
	// its URLs survive the round trip byte-for-byte, and the escaped fence
	// turns every "&" into "&amp;" — which is precisely the corruption this
	// tool exists to prevent, and which query-string-dense retail URLs hit
	// on nearly every entry.  See wrapFenceCDATA.
	//
	// rating stays untrusted.  The relay authors the *assertion* ("I fetched
	// X at T"), but not the values: Title comes from the fetched page and a
	// URL can carry arbitrary text in its path and query.  Marking this
	// trusted would let any site launder text into a trusted fence by being
	// fetched once.  type=data conveys "this is a record, not prose" without
	// making a claim about the bytes.
	fenced, err := s.wrapFenceCDATA(string(jsonBytes), FenceTypeData, FenceUntrusted, "mcp-searxng-relay:session-history")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap fence: %w", err)
	}

	// Counted here rather than derived from the eviction counter: this is
	// the number that answers "did an agent write an answer against an
	// incomplete list", which is the question the cap is tuned against.
	if payload.Elided > 0 {
		s.metrics.SourcesElided.Add(1)
	}

	lg.Info("session sources listed",
		"returned", len(entries),
		"total_fetches", total,
		"elided", payload.Elided,
		"since_seq", in.SinceSeq)

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fenced}},
	}, nil, nil
}

// newFetchHistoryCache builds the per-caller history cache.  Split out so
// NewServer stays readable and so tests can construct one directly.
//
// onEvict fires when a caller is pushed out of the cache entirely, losing its
// whole ledger.  That is invisible from inside the response — the caller just
// sees an empty list, indistinguishable from having fetched nothing — so it is
// worth counting.  May be nil in tests.
func newFetchHistoryCache(onEvict func()) *lru.Cache[string, *fetchHistory] {
	c, err := lru.NewWithEvict(fetchHistoryCallers, func(string, *fetchHistory) {
		if onEvict != nil {
			onEvict()
		}
	})
	if err != nil {
		// Only fails for size <= 0, and the size is a positive constant.
		panic("failed to initialise fetch history cache: " + err.Error())
	}
	return c
}
