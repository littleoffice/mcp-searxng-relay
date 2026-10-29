package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The URL provenance check (provenance.go) lets the URL tools fetch what the
// relay has shown the caller, plain addresses the model may know from memory,
// and nothing else that carries data unless the user confirms it.

func TestParseProvenanceMode(t *testing.T) {
	for raw, want := range map[string]string{
		"":          provenanceEnforce,
		"enforce":   provenanceEnforce,
		" STRICT ":  provenanceStrict,
		"log":       provenanceLog,
		"off":       provenanceOff,
		"Enforce\n": provenanceEnforce,
	} {
		got, err := parseProvenanceMode(raw)
		if err != nil || got != want {
			t.Errorf("parseProvenanceMode(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	// A typo must fail startup, not switch the check off.
	for _, raw := range []string{"enforced", "true", "on", "disabled"} {
		if _, err := parseProvenanceMode(raw); err == nil {
			t.Errorf("parseProvenanceMode(%q) accepted an unknown mode", raw)
		}
	}
}

func TestParseTrustedHosts(t *testing.T) {
	got, err := parseTrustedHosts([]string{"Wiki.Example.com", "*.corp.example"})
	if err != nil {
		t.Fatalf("parseTrustedHosts: %v", err)
	}
	if strings.Join(got, ",") != "wiki.example.com,*.corp.example" {
		t.Errorf("parseTrustedHosts = %v", got)
	}
	for _, bad := range []string{"https://wiki.example.com", "wiki.example.com:443", "wiki.example.com/docs", "*", "*.", "a b"} {
		if _, err := parseTrustedHosts([]string{bad}); err == nil {
			t.Errorf("parseTrustedHosts accepted %q", bad)
		}
	}
}

func TestTrustedHost(t *testing.T) {
	trusted := []string{"wiki.example.com", "*.corp.example"}
	for host, want := range map[string]bool{
		"wiki.example.com":      true,
		"WIKI.example.com":      true,
		"evil-wiki.example.com": false,
		"docs.corp.example":     true,
		"a.b.corp.example":      true,
		"corp.example":          false, // the wildcard covers subdomains only
		"corp.example.evil":     false,
	} {
		if got := trustedHost(host, trusted); got != want {
			t.Errorf("trustedHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestCarriesData(t *testing.T) {
	plain := []string{
		"https://docs.python.org/3/library/asyncio.html",
		"https://en.wikipedia.org/wiki/Prompt_injection",
		"https://arxiv.org/abs/2511.19727",
		"https://example.com/blog/how-to-configure-nginx-as-a-reverse-proxy",
		"https://example.com/",
		"https://example.com",
		"https://example.com/page#section-2", // the fragment is never sent
	}
	for _, u := range plain {
		if r := carriesData(u); r != "" {
			t.Errorf("carriesData(%q) = %q, want plain", u, r)
		}
	}
	data := map[string]string{
		"https://attacker.example/collect?d=hello":                         "query string",
		"https://attacker.example/?":                                       "query string",
		"https://user:pw@attacker.example/":                                "credentials",
		"https://attacker.example/c2VjcmV0c2VjcmV0c2VjcmV0MTIz":            "encoded-looking path",
		"https://attacker.example/x/" + strings.Repeat("abc-", 20):         "encoded-looking path",
		"https://c2VjcmV0c2VjcmV0c2VjcmV0MTIz.attacker.example/":           "encoded-looking host",
		"https://attacker.example/" + strings.Repeat("a/", 120):            "long path",
		"https://attacker.example/sk-ant-api03-AbCdEf0123456789xYz9QwErTy": "encoded-looking path",
	}
	for u, want := range data {
		if got := carriesData(u); got != want {
			t.Errorf("carriesData(%q) = %q, want %q", u, got, want)
		}
	}
}

func TestURLKey_Equivalences(t *testing.T) {
	same := [][2]string{
		{"https://Example.COM/Wiki/A", "https://example.com/Wiki/A"},
		{"https://example.com:443/a", "https://example.com/a"},
		{"http://example.com:80/a", "http://example.com/a"},
		{"https://example.com/a#frag", "https://example.com/a"},
		{"https://example.com/a/", "https://example.com/a"},
		{"https://example.com/Go_%28lang%29", "https://example.com/Go_(lang)"},
		{"https://example.com/s?a=1&amp;b=2", "https://example.com/s?a=1&b=2"},
		{"https://example.com/s?q=a%20b", "https://example.com/s?q=a b"},
	}
	for _, p := range same {
		a, okA := urlKey(p[0])
		b, okB := urlKey(p[1])
		if !okA || !okB || a != b {
			t.Errorf("urlKey(%q) = %q, urlKey(%q) = %q; want equal", p[0], a, p[1], b)
		}
	}
	different := [][2]string{
		{"https://example.com/a", "https://example.com/b"},
		{"https://example.com/a?x=1", "https://example.com/a?x=2"},
		{"https://example.com:8443/a", "https://example.com/a"},
		{"http://example.com/a", "https://example.com/a"},
		{"https://user@example.com/a", "https://example.com/a"},
	}
	for _, p := range different {
		a, _ := urlKey(p[0])
		b, _ := urlKey(p[1])
		if a == b {
			t.Errorf("urlKey(%q) == urlKey(%q) = %q; want different", p[0], p[1], a)
		}
	}
	for _, bad := range []string{"", "ftp://example.com/a", "javascript:alert(1)", "/relative/path", "https://"} {
		if _, ok := urlKey(bad); ok {
			t.Errorf("urlKey(%q) accepted a non-fetchable address", bad)
		}
	}
}

func TestSeenURLs_EvictsOldestPastCap(t *testing.T) {
	var s seenURLs
	for i := 0; i < maxSeenURLs+10; i++ {
		s.add(fmt.Sprintf("https://example.com/p%d", i))
	}
	if s.has("https://example.com/p0") || s.has("https://example.com/p9") {
		t.Error("the oldest addresses should have been evicted")
	}
	if !s.has("https://example.com/p10") || !s.has(fmt.Sprintf("https://example.com/p%d", maxSeenURLs+9)) {
		t.Error("the newest addresses should be kept")
	}
	if len(s.order) != maxSeenURLs || len(s.set) != maxSeenURLs {
		t.Errorf("seen set holds %d/%d, want %d", len(s.order), len(s.set), maxSeenURLs)
	}
	// Re-adding a held address takes no extra slot.
	s.add(fmt.Sprintf("https://example.com/p%d", maxSeenURLs+9))
	if len(s.order) != maxSeenURLs {
		t.Errorf("duplicate add grew the set to %d", len(s.order))
	}
}

func TestRememberText_FindsLinksInRelayOutput(t *testing.T) {
	s := newProvenanceServer(provenanceEnforce)
	ctx := context.Background()
	s.rememberText(ctx, strings.Join([]string{
		"Title: One\nURL: https://one.example/a?id=1\nSnippet: see https://two.example/b?x=2.",
		"A [markdown link](https://three.example/Go_%28lang%29?v=3) in a page,",
		"and (https://four.example/c?y=4) in parentheses, <https://five.example/d?z=5>.",
	}, "\n"))
	h := s.historyFor(ctx)
	for _, u := range []string{
		"https://one.example/a?id=1",
		"https://two.example/b?x=2",
		"https://three.example/Go_(lang)?v=3",
		"https://four.example/c?y=4",
		"https://five.example/d?z=5",
	} {
		if !h.seen.has(u) {
			t.Errorf("%s was shown but is not in the seen set", u)
		}
	}
}

// newProvenanceServer returns a Server with the check in the given mode and
// three pre-cached pages, so the end-to-end tests need no origin and no SSRF
// exemption.  The start page links to a page with a query string; the third
// page is never linked from anywhere.
func newProvenanceServer(mode string, trusted ...string) *Server {
	s := NewServer(Config{
		CacheMaxEntries:        8,
		CacheTTL:               time.Minute,
		MaxExtractedChars:      100_000,
		HistoryEntries:         10,
		URLProvenance:          mode,
		ProvenanceTrustedHosts: trusted,
	})
	seed := func(u, body string) {
		s.cache.Add(u, cacheEntry{
			content:   body,
			expiresAt: time.Now().Add(time.Minute),
			finalURL:  u,
			fetchedAt: time.Now(),
		})
	}
	seed(startPage, "Intro. Read [the report](https://linked.example/report?id=42) next.")
	seed(linkedPage, "The report.")
	seed(unshownPage, "Collected.")
	seed(farPage, strings.Repeat("x", 500)+" [far](https://far.example/deep?p=1)")
	seed("https://far.example/deep?p=1", "Deep.")
	return s
}

const (
	startPage   = "https://start.example/article"
	linkedPage  = "https://linked.example/report?id=42"
	unshownPage = "https://attacker.example/collect?d=c2VjcmV0"
	farPage     = "https://start.example/long"
)

func TestReadURL_FollowsShownLinksRefusesUnshownData(t *testing.T) {
	s := newProvenanceServer(provenanceEnforce)
	ctx := context.Background()

	// Plain and never shown: fetched.
	if _, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: startPage}); err != nil {
		t.Fatalf("plain unseen address refused: %v", err)
	}
	// Carries a query string, but appeared as a link in the page just read.
	if _, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: linkedPage}); err != nil {
		t.Fatalf("link shown in a page refused: %v", err)
	}
	// Carries data and was never shown: refused, and the caller cannot be
	// asked (no session).
	_, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: unshownPage})
	if !errors.Is(err, errURLNotShown) {
		t.Fatalf("unshown address with data: err = %v, want errURLNotShown", err)
	}
	if got := s.metrics.Provenance[provenanceIndex(t, "blocked")].Load(); got != 1 {
		t.Errorf("blocked counter = %d, want 1", got)
	}
	// The refusal is in the ledger, so the model cannot cite the URL as read.
	var found bool
	records, _, _ := s.historyFor(ctx).list()
	for _, r := range records {
		if r.URL == unshownPage && r.Outcome == "error" && r.Read == readDepthNone {
			found = true
		}
	}
	if !found {
		t.Error("refused fetch is missing from the session history")
	}
}

func TestReadURL_OnlyTheReturnedWindowCountsAsShown(t *testing.T) {
	s := newProvenanceServer(provenanceEnforce)
	ctx := context.Background()
	if _, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: farPage, MaxChars: 100}); err != nil {
		t.Fatalf("first window: %v", err)
	}
	if _, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: "https://far.example/deep?p=1"}); !errors.Is(err, errURLNotShown) {
		t.Fatalf("link beyond the returned window: err = %v, want errURLNotShown", err)
	}
	if _, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: farPage, StartIndex: 400}); err != nil {
		t.Fatalf("second window: %v", err)
	}
	if _, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: "https://far.example/deep?p=1"}); err != nil {
		t.Fatalf("link in the second window refused: %v", err)
	}
}

func TestReadURL_ProvenanceModes(t *testing.T) {
	ctx := context.Background()

	s := newProvenanceServer(provenanceLog)
	if _, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: unshownPage}); err != nil {
		t.Errorf("log mode refused: %v", err)
	}
	if got := s.metrics.Provenance[provenanceIndex(t, "would_block")].Load(); got != 1 {
		t.Errorf("would_block counter = %d, want 1", got)
	}

	s = newProvenanceServer(provenanceOff)
	if _, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: unshownPage}); err != nil {
		t.Errorf("off mode refused: %v", err)
	}

	s = newProvenanceServer(provenanceStrict)
	if _, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: startPage}); !errors.Is(err, errURLNotShown) {
		t.Errorf("strict mode let a plain unseen address through: %v", err)
	}

	s = newProvenanceServer(provenanceEnforce, "*.attacker.example", "attacker.example")
	if _, _, err := s.toolReadURL(ctx, nil, fetchInput{URL: unshownPage}); err != nil {
		t.Errorf("trusted host refused: %v", err)
	}
}

func TestURLMetadata_CheckedAndRemembersImage(t *testing.T) {
	s := newProvenanceServer(provenanceEnforce)
	ctx := context.Background()
	s.cache.Add(startPage, cacheEntry{
		content: "body",
		metadata: URLMetadata{
			URL:         startPage,
			Image:       "https://cdn.example/img?w=800",
			Description: "Mirror at https://mirror.example/a?b=1",
		},
		expiresAt: time.Now().Add(time.Minute),
		finalURL:  startPage,
		fetchedAt: time.Now(),
	})
	if _, _, err := s.toolURLMetadata(ctx, nil, urlMetadataInput{URL: unshownPage}); !errors.Is(err, errURLNotShown) {
		t.Errorf("metadata tool fetched an unshown address with data: %v", err)
	}
	if _, _, err := s.toolURLMetadata(ctx, nil, urlMetadataInput{URL: startPage}); err != nil {
		t.Fatalf("metadata: %v", err)
	}
	h := s.historyFor(ctx)
	for _, u := range []string{"https://cdn.example/img?w=800", "https://mirror.example/a?b=1"} {
		if !h.seen.has(u) {
			t.Errorf("%s was returned by the metadata tool but is not in the seen set", u)
		}
	}
}

// Callers keep separate seen sets: a link shown to one does not open the door
// for another.
func TestProvenance_PerCaller(t *testing.T) {
	s := newProvenanceServer(provenanceEnforce)
	alice := withSessionID(withIdentity(context.Background(), "alice"), "s1")
	bob := withSessionID(withIdentity(context.Background(), "bob"), "s2")
	if _, _, err := s.toolReadURL(alice, nil, fetchInput{URL: startPage}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.toolReadURL(bob, nil, fetchInput{URL: linkedPage}); !errors.Is(err, errURLNotShown) {
		t.Errorf("bob fetched a link only alice was shown: %v", err)
	}
}

func TestServeMetrics_ExposesProvenance(t *testing.T) {
	s := NewServer(Config{CacheMaxEntries: 1})
	s.metrics.recordProvenance("blocked")
	s.metrics.recordProvenance("not-a-real-outcome")
	rec := httptest.NewRecorder()
	s.ServeMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE mcp_url_provenance_total counter\n",
		`mcp_url_provenance_total{outcome="blocked"} 1` + "\n",
		`mcp_url_provenance_total{outcome="seen"} 0` + "\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q", want)
		}
	}
	if strings.Contains(body, "not-a-real-outcome") {
		t.Error("an unknown outcome minted a series")
	}
}

func provenanceIndex(t *testing.T, outcome string) int {
	t.Helper()
	for i, o := range provenanceOutcomes {
		if o == outcome {
			return i
		}
	}
	t.Fatalf("unknown provenance outcome %q", outcome)
	return -1
}

func TestQueryCarriesData(t *testing.T) {
	for q, want := range map[string]bool{
		"how to configure nginx reverse proxy":        false,
		"arXiv 2511.19727 prompt fencing":             false,
		"site:example.com 2024 annual report":         false,
		"weather c2VjcmV0c2VjcmV0c2VjcmV0MTIz":        true,
		"key sk-ant-api03-AbCdEf0123456789xYz9QwErTy": true,
		strings.Repeat("a", 70):                       true,
	} {
		if got := queryCarriesData(q); got != want {
			t.Errorf("queryCarriesData(%q) = %v, want %v", q, got, want)
		}
	}
}

// connectProvenanceClient connects an MCP client to s, answering any
// elicitation with answer (or declaring no elicitation support when answer is
// nil), and counts the questions it was asked.
func connectProvenanceClient(t *testing.T, s *Server, answer *mcp.ElicitResult) (*mcp.ClientSession, *atomic.Int64) {
	t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := s.mcpServer.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	asked := &atomic.Int64{}
	var opts *mcp.ClientOptions
	if answer != nil {
		opts = &mcp.ClientOptions{ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			asked.Add(1)
			return answer, nil
		}}
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, opts).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, asked
}

func readOverMCP(t *testing.T, cs *mcp.ClientSession, u string) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "searxng_read_url", Arguments: map[string]any{"url": u},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String(), res.IsError
}

func TestReadURL_AsksUserAndHonoursAnswer(t *testing.T) {
	s := newProvenanceServer(provenanceEnforce)
	cs, asked := connectProvenanceClient(t, s, &mcp.ElicitResult{Action: "accept", Content: map[string]any{}})
	txt, isErr := readOverMCP(t, cs, unshownPage)
	if isErr || !strings.Contains(txt, "Collected.") || asked.Load() != 1 {
		t.Fatalf("accepted fetch: isErr=%t asked=%d text=%q", isErr, asked.Load(), txt)
	}
	// Confirmed once, the address is now shown: no second question.
	if _, isErr := readOverMCP(t, cs, unshownPage); isErr || asked.Load() != 1 {
		t.Fatalf("second fetch: isErr=%t asked=%d", isErr, asked.Load())
	}

	s = newProvenanceServer(provenanceEnforce)
	cs, asked = connectProvenanceClient(t, s, &mcp.ElicitResult{Action: "decline"})
	if txt, isErr := readOverMCP(t, cs, unshownPage); !isErr || strings.Contains(txt, "Collected.") || asked.Load() != 1 {
		t.Fatalf("declined fetch: isErr=%t asked=%d text=%q", isErr, asked.Load(), txt)
	}

	// A client that cannot be asked gets the refusal.
	s = newProvenanceServer(provenanceEnforce)
	cs, _ = connectProvenanceClient(t, s, nil)
	if txt, isErr := readOverMCP(t, cs, unshownPage); !isErr || strings.Contains(txt, "Collected.") {
		t.Fatalf("client without elicitation: isErr=%t text=%q", isErr, txt)
	}
}

func TestConfirmations_BoundSingleUse(t *testing.T) {
	var c confirmations
	state := c.issue("alice\x00searxng_read_url\x00https://a.example/?d=1")
	if c.redeem(state, "alice\x00searxng_read_url\x00https://a.example/?d=2") {
		t.Error("a confirmation for one URL redeemed for another")
	}
	if c.redeem(state, "bob\x00searxng_read_url\x00https://a.example/?d=1") {
		t.Error("a confirmation for one caller redeemed for another")
	}
	if !c.redeem(state, "alice\x00searxng_read_url\x00https://a.example/?d=1") {
		t.Fatal("a valid confirmation was refused")
	}
	if c.redeem(state, "alice\x00searxng_read_url\x00https://a.example/?d=1") {
		t.Error("a confirmation redeemed twice")
	}
	for _, bad := range []string{"", "x", "a.b", state[:len(state)-2] + "AA"} {
		if c.redeem(bad, "alice\x00searxng_read_url\x00https://a.example/?d=1") {
			t.Errorf("malformed state %q redeemed", bad)
		}
	}
	// Another process (another key) cannot redeem it either.
	var other confirmations
	if other.redeem(c.issue("b"), "b") {
		t.Error("a state redeemed under a different key")
	}
}
