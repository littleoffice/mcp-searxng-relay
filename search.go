package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

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

type searxNGResponse struct {
	Results []SearchResult `json:"results"`
}

func (s *Server) toolSearch(
	ctx context.Context,
	req *mcp.CallToolRequest,
	in searchInput,
) (*mcp.CallToolResult, any, error) {
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

	results, err := s.search(ctx, in.Query, pageno, in.Categories, language, in.TimeRange, safesearch, engines)
	if err != nil {
		s.metrics.SearchErrors.Add(1)
		slog.Error("search failed",
			"query", in.Query, "error", err,
			"identity", identityFromContext(ctx),
			"session_id", sessionIDOf(req))
		return nil, nil, err
	}
	s.metrics.SearchTotal.Add(1)

	// Truncate to the requested number of results.
	if len(results) > numResults {
		results = results[:numResults]
	}

	slog.Info("search completed",
		"query", in.Query, "page", pageno,
		"results", len(results), "categories", in.Categories,
		"engines", engines,
		"identity", identityFromContext(ctx),
		"session_id", sessionIDOf(req))

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
		slog.Warn("searxng returned non-200",
			"status", resp.StatusCode,
			"url", u.String(),
			"hint", "ensure JSON format is enabled in settings.yml")
		return nil, fmt.Errorf("search backend returned HTTP %d", resp.StatusCode)
	}

	var searxResp searxNGResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10_000_000)).Decode(&searxResp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	return searxResp.Results, nil
}
