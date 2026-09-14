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
)

// maxDiscoveredEngines caps how many auto-discovered engines are advertised in
// the always-on search tool description, so an instance with a large enabled
// set (stock SearXNG enables 100+) cannot bloat the tool-definitions prefix
// that ships on every request. Manual SEARXNG_ENGINES / _FILE entries are not
// counted against this cap. An operator who needs more discovered engines
// should scope them with SEARXNG_ENGINES_DISCOVER_CATEGORIES rather than raise
// this, since the constraint is context budget, not correctness.
const maxDiscoveredEngines = 40

// searxngConfigEngine is the subset of one /config "engines" entry we consume.
// SearXNG returns more per engine (shortcut, paging, timeout, …); we ignore
// the rest so an upstream schema addition can't break decoding.
type searxngConfigEngine struct {
	Name       string   `json:"name"`
	Categories []string `json:"categories"`
	Enabled    bool     `json:"enabled"`
}

// searxngConfigResponse is the slice of GET /config we decode.
type searxngConfigResponse struct {
	Engines []searxngConfigEngine `json:"engines"`
}

// discoverEngines fetches {SEARXNG_URL}/config and returns a roster of the
// instance's enabled engines, filtered by cfg.DiscoverCategories (a category
// allowlist; empty means every category) and cfg.ExcludeEngines (names never
// advertised), capped at maxDiscoveredEngines. Each descriptor's purpose is
// derived compactly from the engine's categories so a discovered entry still
// gives the model a routing hint; a manual roster purpose overrides it when the
// two are merged (see mergeRosters).
//
// The same tokens the search path forwards are sent here, matching how a query
// reaches token-gated engines. Note /config lists engines regardless of tokens,
// so ExcludeEngines — not the token set — is the control for keeping a private
// engine's existence out of the description.
//
// Errors (network failure, non-200, unparseable body) are returned rather than
// fatal: the caller logs and falls back to the manual roster, which is the
// expected path on a hardened instance that blocks /config.
func discoverEngines(ctx context.Context, cfg Config, client *http.Client, logger *slog.Logger) ([]engineDescriptor, error) {
	endpoint, err := url.Parse(cfg.SearxngURL + "/config")
	if err != nil {
		return nil, fmt.Errorf("invalid SEARXNG_URL: %w", err)
	}
	if len(cfg.SearxngTokens) > 0 {
		q := endpoint.Query()
		q.Set("tokens", strings.Join(cfg.SearxngTokens, ","))
		endpoint.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build /config request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if cfg.UserAgent != "" {
		req.Header.Set("User-Agent", cfg.UserAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET /config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/config returned HTTP %d", resp.StatusCode)
	}

	var parsed searxngConfigResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 5_000_000)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("parse /config JSON: %w", err)
	}

	allow := sliceToSet(cfg.DiscoverCategories)
	exclude := sliceToSet(cfg.ExcludeEngines)

	var roster []engineDescriptor
	for _, e := range parsed.Engines {
		if !e.Enabled {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(e.Name))
		if name == "" || exclude[name] {
			continue
		}
		if len(allow) > 0 && !anyInSet(e.Categories, allow) {
			continue
		}
		roster = append(roster, engineDescriptor{Name: name, Purpose: discoveredPurpose(e.Categories)})
		if len(roster) == maxDiscoveredEngines {
			if logger != nil {
				logger.Warn("engine discovery hit the advertised-engine cap; "+
					"advertising the first matches only — scope with "+
					"SEARXNG_ENGINES_DISCOVER_CATEGORIES to choose which",
					"cap", maxDiscoveredEngines)
			}
			break
		}
	}
	if logger != nil {
		logger.Info("discovered engines from SearXNG /config", "count", len(roster))
	}
	return roster, nil
}

// discoveredPurpose builds a compact purpose line from an engine's categories,
// lowercased and de-duplicated in first-seen order, e.g. "it, general". It is
// empty when the engine reports no categories — a name-only entry still tells
// the model the engine exists, and a manual purpose can fill it in.
func discoveredPurpose(categories []string) string {
	seen := make(map[string]struct{}, len(categories))
	cats := make([]string, 0, len(categories))
	for _, c := range categories {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		cats = append(cats, c)
	}
	return strings.Join(cats, ", ")
}

// sliceToSet builds a lookup set from an already-lowercased slice, returning nil
// (a valid empty lookup) for an empty input.
func sliceToSet(ss []string) map[string]bool {
	if len(ss) == 0 {
		return nil
	}
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// anyInSet reports whether any of vals (lowercased and trimmed here) is present
// in set. A nil set yields false.
func anyInSet(vals []string, set map[string]bool) bool {
	for _, v := range vals {
		if set[strings.ToLower(strings.TrimSpace(v))] {
			return true
		}
	}
	return false
}
