package main

import (
	"context"
	"encoding/json"
	"fmt"
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
// entire history in a fixed-size ring.  The obvious alternative — one flat LRU
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
	// fetchHistoryEntries is the per-caller ring size.  The list is read
	// into the context window on every call, so this is a token budget as
	// much as a memory one: 50 entries is far more than a single research
	// task produces and still costs well under a page of context.  Older
	// entries are reported as a count rather than dropped silently.
	fetchHistoryEntries = 50

	// fetchHistoryCallers bounds how many distinct callers we retain
	// histories for.  Matched to maxSessions so the history cache cannot
	// outgrow the session cap that already bounds this process.  Worst
	// case is ~1000 × 50 small records, which is negligible next to the
	// content cache (CACHE_MAX_ENTRIES × MAX_EXTRACTED_CHARS).
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
}

// fetchHistory is a fixed-size ring of fetchRecords for one caller.
//
// The mutex is not redundant with the LRU's own locking.  The cache returns a
// *fetchHistory, and two concurrent requests from the same caller then write
// through the same pointer; the cache's lock protects its map, not the value
// behind the pointer.
type fetchHistory struct {
	mu    sync.Mutex
	ring  [fetchHistoryEntries]fetchRecord
	next  int // index of the next slot to write (== oldest, once wrapped)
	count int // entries currently held, capped at fetchHistoryEntries
	total int // entries ever appended; source of Seq
}

// appendRecord stores r, assigning it the next sequence number, and returns
// the assigned Seq.
//
// Sequence numbers are monotonic per caller and are what the model uses to
// order the list.  A timestamp answers "how stale is this"; a sequence number
// answers "what did I do most recently", and only the second is needed to pick
// the right URL out of a list.  Both are carried because they are different
// questions — a cache hit at seq 47 can legitimately hold bytes retrieved at
// seq 3.
func (h *fetchHistory) appendRecord(r fetchRecord) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.total++
	r.Seq = h.total
	h.ring[h.next] = r
	h.next = (h.next + 1) % fetchHistoryEntries
	if h.count < fetchHistoryEntries {
		h.count++
	}
	return r.Seq
}

// list returns the retained records newest-first, along with the total number
// ever appended for this caller.
//
// Newest-first is deliberate: it makes recency positional, so the model reads
// the ordering off the list rather than inferring it from sequence arithmetic.
func (h *fetchHistory) list() (records []fetchRecord, total int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	records = make([]fetchRecord, 0, h.count)
	for i := 1; i <= h.count; i++ {
		idx := ((h.next-i)%fetchHistoryEntries + fetchHistoryEntries) % fetchHistoryEntries
		records = append(records, h.ring[idx])
	}
	return records, h.total
}

// historyKey derives the cache key for the current caller.
//
// Keying on session ID alone is unsafe here.  Under MCP_STATELESS the session
// ID is client-asserted and is not validated by the SDK, and the README
// documents a supported configuration in which it is empty for every request.
// Either way, several callers would collapse onto one key and a caller could
// be handed another caller's fetched URLs — a cross-tenant leak in exactly the
// deployments this project is aimed at.
//
// Identity is server-validated in both session modes, so pairing the two keeps
// callers separated even when the session half is empty, forged, or shared.
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
	h := &fetchHistory{}
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
	h.appendRecord(r)
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
	ctx = withSessionID(ctx, sessionIDOf(req))
	lg := callerLogger(ctx)
	s.metrics.SourcesTotal.Add(1)

	h := s.historyFor(ctx)
	var records []fetchRecord
	var total int
	if h != nil {
		records, total = h.list()
	}

	// Deduplicate by the citable URL, keeping the newest record for each.
	// Iteration is already newest-first, so first-seen wins and later hits
	// only contribute to the repeat count.
	seen := make(map[string]int, len(records))
	entries := make([]sourceEntry, 0, len(records))
	for _, r := range records {
		if r.Seq <= in.SinceSeq {
			continue
		}
		citable := r.FinalURL
		if citable == "" {
			citable = r.URL
		}
		if idx, ok := seen[citable]; ok {
			entries[idx].Fetches++
			continue
		}
		e := sourceEntry{
			URL:        citable,
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
			Fetches:    1,
		}
		// Only surface the requested URL when a redirect moved it; the
		// two being equal is the common case and the extra field would
		// be noise the model has to disambiguate.
		if r.FinalURL != "" && r.FinalURL != r.URL {
			e.RequestedURL = r.URL
		}
		seen[citable] = len(entries)
		entries = append(entries, e)
	}

	payload := sourcesPayload{
		Note:     sourcesNote,
		Total:    total,
		Returned: len(entries),
		Elided:   total - len(records),
		Sources:  entries,
	}
	if payload.Elided < 0 {
		payload.Elided = 0
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
func newFetchHistoryCache() *lru.Cache[string, *fetchHistory] {
	c, err := lru.New[string, *fetchHistory](fetchHistoryCallers)
	if err != nil {
		// Only fails for size <= 0, and the size is a positive constant.
		panic("failed to initialise fetch history cache: " + err.Error())
	}
	return c
}
