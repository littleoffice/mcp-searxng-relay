package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── Tool: search ──────────────────────────────────────────────────────────────
//
// The SDK's mcp.AddTool generic helper infers the JSON Schema from this
// struct's tags. `omitempty` makes a field optional in the inferred schema;
// fields without it are required. The `jsonschema:"..."` tag becomes the
// property's `description` in the schema.
//
// All numeric defaults and clamps are applied in the handler body, since the
// distinction between "absent" and "explicit zero" is not meaningful for our
// optional ints.

type searchInput struct {
	Query      string `json:"query"                jsonschema:"the search query"`
	NumResults int    `json:"num_results,omitempty" jsonschema:"number of results to return (default: 10, max: 20)"`
	Pageno     int    `json:"pageno,omitempty"      jsonschema:"page number, starting at 1 (default: 1)"`
	Categories string `json:"categories,omitempty"  jsonschema:"comma-separated SearXNG categories e.g. 'news', 'science', 'files', 'images' (default: general web)"`
	Language   string `json:"language,omitempty"    jsonschema:"language code e.g. 'en', 'de', or 'all' (default: all)"`
	TimeRange  string `json:"time_range,omitempty"  jsonschema:"filter by time: 'day', 'month', or 'year'"`
	Engines    string `json:"engines,omitempty"     jsonschema:"comma-separated SearXNG engine names to query, e.g. 'wikipedia,github' — engine names appear in the engine field of prior results; unknown names are silently ignored by SearXNG (default: instance's configured engines)"`
	Safesearch int    `json:"safesearch,omitempty"  jsonschema:"safe search level: 0 = off, 1 = moderate, 2 = strict (default: 0)"`
}

// SearchResult is the parsed shape of a single SearXNG result entry.
//
// The Engines field is the list of backend engines that returned this URL.
// SearXNG already deduplicates across engines internally and exposes the
// aggregated list on each result; we pass it through so the consuming agent
// can weigh corroboration (a URL returned by three engines is a different
// signal than one returned by one). No scoring is applied on top — that is
// an editorial decision and is left to the agent.
type SearchResult struct {
	Title   string   `json:"title"`
	URL     string   `json:"url"`
	Snippet string   `json:"content"` // SearXNG uses "content" not "snippet"
	Engines []string `json:"engines,omitempty"`
}

// searxNGResponse is the subset of SearXNG's format=json body this relay
// reads.  Upstream builds it in searx/webutils.py:get_json_response, whose
// full key set is query, results, answers, corrections, infoboxes,
// suggestions and unresponsive_engines.
type searxNGResponse struct {
	Results []SearchResult `json:"results"`

	// UnresponsiveEngines names the backends that failed to answer this
	// query.  Upstream shape is a list of two-element arrays,
	// [engine_name, message] — Python tuples from get_translated_errors,
	// where the message is localised and gains a "Suspended: " prefix when
	// the engine is in cooldown.
	//
	// Kept as RawMessage and decoded separately rather than typed directly
	// as [][]string, because a strict decode here would fail the WHOLE
	// response if upstream ever changed this field's shape — turning a
	// diagnostic nicety into a total search outage.  Engine health is
	// metadata about the answer; it must never be able to take the answer
	// down with it.  parseUnresponsiveEngines degrades to "no engine
	// information" instead.
	UnresponsiveEngines json.RawMessage `json:"unresponsive_engines"`
}

// engineFailure is one backend that did not answer, as reported by SearXNG.
type engineFailure struct {
	Engine string
	Reason string
}

// parseUnresponsiveEngines decodes the unresponsive_engines field.  Returns
// nil for absent, empty, or unrecognised input — every failure mode here is
// "we learned nothing about engine health", never an error that propagates.
//
// Entries with fewer than two elements are skipped rather than padded: a
// shape we do not recognise is not something to guess at, and a half-parsed
// engine name in a log line is worse than its absence.
func parseUnresponsiveEngines(raw json.RawMessage) []engineFailure {
	if len(raw) == 0 {
		return nil
	}
	var pairs [][]string
	if err := json.Unmarshal(raw, &pairs); err != nil {
		return nil
	}
	out := make([]engineFailure, 0, len(pairs))
	for _, p := range pairs {
		if len(p) < 2 || p[0] == "" {
			continue
		}
		out = append(out, engineFailure{Engine: p[0], Reason: p[1]})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// engineNames returns just the backend names, for the compact field of the
// degraded-search log line.
func engineNames(fs []engineFailure) []string {
	names := make([]string, 0, len(fs))
	for _, f := range fs {
		names = append(names, f.Engine)
	}
	return names
}

// engineFailureDetail renders "engine: reason" pairs for the verbose field of
// the same log line.  Two fields rather than one because they answer
// different questions: the names are what you alert on and group by, the
// reasons are what you read once the alert fires.
func engineFailureDetail(fs []engineFailure) []string {
	detail := make([]string, 0, len(fs))
	for _, f := range fs {
		detail = append(detail, f.Engine+": "+f.Reason)
	}
	return detail
}

func (s *Server) toolSearch(
	ctx context.Context,
	req *mcp.CallToolRequest,
	in searchInput,
) (*mcp.CallToolResult, any, error) {
	// Bind the session ID into the context once, so the search pipeline
	// below inherits full caller attribution without taking the request.
	ctx = withSessionID(ctx, sessionIDOf(ctx, req))
	lg := callerLogger(ctx)

	if in.Query == "" {
		return nil, nil, fmt.Errorf("query argument is required")
	}

	numResults := in.NumResults
	if numResults < 1 {
		numResults = 10
	} else if numResults > 20 {
		numResults = 20
	}

	pageno := in.Pageno
	if pageno < 1 {
		pageno = 1
	} else if pageno > 100 {
		pageno = 100
	}

	language := in.Language
	if language == "" {
		language = "all"
	}

	safesearch := in.Safesearch
	if safesearch < 0 {
		safesearch = 0
	} else if safesearch > 2 {
		safesearch = 2
	}

	// Normalize the engines list the same way config CSV values are
	// handled: trim entries, drop empties.  " Wikipedia, github " becomes
	// "wikipedia,github".  Lowercasing matters because SearXNG engine
	// names are lowercase identifiers and a case-mismatched name would be
	// silently ignored — the agent copied the name from a result's engine
	// field, but users typing by hand won't always match case.
	engines := strings.Join(parseCSV(strings.ToLower(in.Engines)), ",")

	searchStart := time.Now()
	results, err := s.search(ctx, in.Query, pageno, in.Categories, language, in.TimeRange, safesearch, engines)
	s.metrics.SearchDuration.Observe(time.Since(searchStart))
	if err != nil {
		s.metrics.SearchErrors.Add(1)
		lg.Error("search failed",
			"query", in.Query, "error", err)
		return nil, nil, err
	}
	s.metrics.SearchTotal.Add(1)

	// Truncate to the requested number of results.
	if len(results) > numResults {
		results = results[:numResults]
	}

	lg.Info("search completed",
		"query", in.Query, "page", pageno,
		"results", len(results), "categories", in.Categories,
		"engines", engines)

	if len(results) == 0 {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "No results found."}},
		}, nil, nil
	}

	var sb strings.Builder
	for i, r := range results {
		if i > 0 {
			sb.WriteString("\n---\n")
		}
		_, _ = fmt.Fprintf(&sb, "Title: %s\nURL: %s\nSnippet: %s\n", r.Title, r.URL, r.Snippet)
		if len(r.Engines) > 0 {
			_, _ = fmt.Fprintf(&sb, "Engines: %s\n", strings.Join(r.Engines, ", "))
		}
	}

	fenced, err := s.wrapFence(sb.String(), FenceTypeContent, FenceUntrusted, s.config.SearxngURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap fence: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fenced}},
	}, nil, nil
}

func (s *Server) search(
	ctx context.Context,
	query string,
	page int,
	categories, lang, timeRange string,
	safesearch int,
	engines string,
) ([]SearchResult, error) {
	u, err := url.Parse(s.config.SearxngURL + "/search")
	if err != nil {
		return nil, fmt.Errorf("invalid SEARXNG_URL: %w", err)
	}

	q := u.Query()
	q.Set("q", query)
	q.Set("format", "json")
	q.Set("pageno", fmt.Sprintf("%d", page))
	q.Set("safesearch", fmt.Sprintf("%d", safesearch))
	if categories != "" {
		q.Set("categories", categories)
	}
	if lang != "all" && lang != "" {
		q.Set("language", lang)
	}
	if timeRange != "" {
		q.Set("time_range", timeRange)
	}
	if engines != "" {
		q.Set("engines", engines)
	}
	// Private-engine tokens.  SearXNG resolves the full engine reference list
	// first — categories, the `engines` parameter, and `!bang` syntax inside
	// the query alike — and then drops every engine whose `tokens:` list is
	// not satisfied by what the caller presented.  Sending them here is
	// therefore what makes a tokenised engine reachable at all, and omitting
	// them is what makes every *other* tenant's engines unreachable from this
	// relay regardless of what the agent asks for.
	if len(s.config.SearxngTokens) > 0 {
		q.Set("tokens", strings.Join(s.config.SearxngTokens, ","))
	}
	u.RawQuery = q.Encode()

	req, err := s.newSearxRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req = req.WithContext(ctx)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		callerLogger(ctx).Warn("searxng returned non-200",
			"status", resp.StatusCode,
			"url", u.String(),
			"hint", "ensure JSON format is enabled in settings.yml")
		return nil, fmt.Errorf("search backend returned HTTP %d", resp.StatusCode)
	}

	var searxResp searxNGResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10_000_000)).Decode(&searxResp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	// A search where some backends failed is not an error — SearXNG returns
	// HTTP 200 with whatever the surviving engines produced — but it is a
	// degraded answer, and until now nothing anywhere said so.  The engines
	// go quiet, results get thinner, the agent's answers get worse, and the
	// first visible symptom is someone concluding the model has regressed.
	// That failure has already cost this project a misdiagnosis: two engines
	// broke on an upstream API change and the relay was suspected first.
	//
	// Warn level, not info: this is the signal an operator needs to see
	// unprompted.  A deployment with many engines configured may see
	// intermittent entries as engines cycle through suspension, which is
	// noisy but correct — the alternative is the silence that caused the
	// misdiagnosis in the first place.
	if failures := parseUnresponsiveEngines(searxResp.UnresponsiveEngines); len(failures) > 0 {
		callerLogger(ctx).Warn("searxng search was degraded: some engines did not respond",
			"unresponsive_engines", strings.Join(engineNames(failures), ","),
			"unresponsive_count", len(failures),
			"detail", strings.Join(engineFailureDetail(failures), "; "),
			"query", query,
			"results", len(searxResp.Results),
			"hint", "results are incomplete; check the named engines in your SearXNG instance before treating thin results as a relay or model problem")
	}

	return searxResp.Results, nil
}
