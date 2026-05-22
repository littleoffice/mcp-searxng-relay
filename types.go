package main

import "time"

// projectName is the canonical name of this binary.  Used for the default
// User-Agent (projectName + "/" + ServerVersion) and as the MCP protocol
// Implementation.Name announced to clients on initialize.  Keep in sync
// with the binary name, the Docker image tag, and the README header — if
// you rename one, rename all of them in the same commit.
const projectName = "mcp-searxng-relay"

// ServerVersion is overridden at link time via -ldflags "-X main.ServerVersion=...".
var ServerVersion = "dev"

// URLMetadata is the structured-metadata view of a fetched URL.  Returned by
// the searxng_url_metadata tool and embedded in cacheEntry so a metadata-only
// fetch and a content fetch can share the same upstream HTTP request.
//
// Fields are intentionally a curated subset of what the extractor reports:
// agent-useful only.  Trafilatura's Hostname is derivable from URL; ID,
// Fingerprint, License, and PageType are either rarely populated or not
// actionable for an agent and so are omitted.
//
// Date is *time.Time rather than time.Time so the `omitempty` JSON tag
// actually omits it when the extractor found no date — encoding/json treats
// a zero time.Time as non-empty otherwise.
type URLMetadata struct {
	URL         string     `json:"url"`
	Title       string     `json:"title,omitempty"`
	Author      string     `json:"author,omitempty"`
	Description string     `json:"description,omitempty"`
	SiteName    string     `json:"site_name,omitempty"`
	Date        *time.Time `json:"date,omitempty"`
	Language    string     `json:"language,omitempty"`
	Image       string     `json:"image,omitempty"`
	Categories  []string   `json:"categories,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
}

// cacheEntry is what we store in the in-memory LRU keyed by URL.  Holds both
// the rendered markdown and the structured metadata so a metadata-only fetch
// followed by a content fetch (or vice versa) does not hit the network twice.
type cacheEntry struct {
	content   string
	metadata  URLMetadata
	expiresAt time.Time
}

// sessionInfo is the per-session metadata we track for audit correlation
// in stateful mode.  Populated by the InitializedHandler when a client
// completes the MCP initialize handshake, read by the janitor to find
// stale sessions, and joined with tool-call log lines (via session_id)
// during forensics.
//
// Not used in stateless mode — there are no persistent sessions to track.
type sessionInfo struct {
	Identity  string    // from the bearer-token table; "" if no auth configured
	CreatedAt time.Time // wall clock at notifications/initialized
}
