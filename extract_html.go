// Package main: extract_html.go — HTML → Markdown extraction pipeline.
//
// Owns the path from a raw HTML body to (a) the structured Markdown returned
// to the model and (b) the curated URLMetadata returned by the metadata tool.
//
//  1. extractHTMLDocument runs trafilatura: it locates the main article
//     subtree, returns it as an *html.Node, and pulls structured metadata
//     from <meta>, OpenGraph, and JSON-LD.  Replaces the previous in-tree
//     content-finding heuristic (selector list + paragraph-density scoring)
//     with a library that encodes a longer track record of edge-case fixes —
//     AMP wrappers, lazy-loaded sections, multi-page articles, etc. — and
//     supplies metadata the previous code did not.
//
//  2. renderMarkdown walks the chosen subtree and emits Markdown, preserving
//     headings, lists, tables, code blocks, and inline emphasis.  Kept
//     in-tree intentionally: the renderer is mechanical, the custom code
//     matches what a library would give us, and not adding html-to-markdown
//     avoids a further dep-tree expansion.  See supply-chain.md.
//
// The renderer is depth-bounded by maxDOMDepth so a pathologically nested
// document cannot exhaust the goroutine stack.
package main

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/markusmobius/go-trafilatura"
	"golang.org/x/net/html"
)

// maxDOMDepth caps DOM-tree recursion in the markdown renderer.  A 500KB
// document of nested <div> elements can have ~45,000 levels; without the cap
// this exhausts the goroutine stack.
const maxDOMDepth = 1000

// maxRenderedChars is the upper bound on the content window returned to the
// agent in a single searxng_read_url response.  It is both the default and
// the ceiling for the tool's max_chars parameter.  Content beyond the window
// is not dropped: extraction keeps up to Config.MaxExtractedChars in the
// cache, and the agent pages through it with start_index (see
// paginateContent in fetch.go).
const maxRenderedChars = 100_000

// ── Extraction ────────────────────────────────────────────────────────────────

// extractHTMLDocument runs the trafilatura extractor over the body and
// returns the extracted content node and the URLMetadata derived from the
// page.  The content node may be nil when trafilatura found no extractable
// article — callers should treat that as "no readable content" rather than
// retrying.
//
// originalURL is the canonical URL of the fetched page.  Trafilatura uses it
// for relative-link resolution and gives metadata URLs precedence over it;
// we also use it as a fallback for URLMetadata.URL when the page contains no
// canonical <link> or og:url.
//
// includeLinks keeps <a> elements in the extracted subtree.  It must be true
// for renderMarkdown to have any hrefs to emit: with the library default
// (false) trafilatura removes anchors in BOTH extraction paths — the main
// path omits "a" from potentialTags, and the fallback path (which this
// codebase enables via EnableFallback) calls StripTags(tree, "a") in
// sanitizeTree.  The same option also gates trafilatura's relative → absolute
// href rewriting against OriginalURL, so with it false the URL below is used
// for metadata only.
func extractHTMLDocument(
	body []byte, originalURL string, includeLinks bool, pruneSelector string,
) (*html.Node, URLMetadata, error) {
	// Parse the URL best-effort: trafilatura accepts a nil OriginalURL and
	// the caller (readURL) has already validated the scheme, so a parse
	// failure here is not worth aborting on.
	parsedURL, _ := url.Parse(originalURL)

	opts := trafilatura.Options{
		OriginalURL:     parsedURL,
		ExcludeComments: true, // user comments are noise for an agent
		Deduplicate:     true, // strip repeated segments (boilerplate, sidebars)
		// EnableFallback turns on the readability and dom-distiller fallback
		// extractors.  Costs roughly 2x extraction time but adds ~1pp of
		// F-score in trafilatura's own benchmark; we pay the dep-tree cost
		// for these packages either way, so the slower-but-better trade
		// is the one that justifies the swap in the first place.
		EnableFallback: true,
		// Upstream marks this "experimental", which in practice means the
		// anchors are preserved but no extra cleaning is applied to them —
		// hence the scheme allow-list and resolution in resolveHref rather
		// than trusting whatever the page supplied.
		IncludeLinks: includeLinks,
		// Applied before subtree selection, which is the whole point: it
		// removes boilerplate containers while the extractor is still
		// deciding what the article is, rather than cleaning up after it
		// has already decided wrongly.  A malformed selector is silently
		// ignored by the library (core.go:127), so it is validated at
		// startup instead — see main().
		PruneSelector: pruneSelector,
	}

	result, err := trafilatura.Extract(bytes.NewReader(body), opts)
	if err != nil || result == nil {
		// Trafilatura reports an error when nothing extractable is found.
		// Return zero values with the original URL populated so the
		// metadata tool still has something well-formed to return.
		meta := URLMetadata{URL: originalURL}
		if err != nil {
			return nil, meta, fmt.Errorf("extractor failed: %w", err)
		}
		return nil, meta, nil
	}

	return result.ContentNode, metadataFromTrafilatura(result.Metadata, originalURL), nil
}

// metadataFromTrafilatura projects trafilatura's Metadata onto our curated
// URLMetadata shape.  The mapping is one-to-one for the fields we expose;
// fields we do not expose (Hostname, ID, Fingerprint, License, PageType) are
// either derivable from URL or not actionable for an agent.
//
// String fields are clamped to defensive maxima — a pathological page with
// a 10KB <title> should not turn into a 10KB metadata response.
func metadataFromTrafilatura(m trafilatura.Metadata, originalURL string) URLMetadata {
	out := URLMetadata{
		URL:         firstNonEmpty(m.URL, originalURL),
		Title:       truncateField(m.Title, 512),
		Author:      truncateField(m.Author, 256),
		Description: truncateField(m.Description, 2048),
		SiteName:    truncateField(m.Sitename, 256),
		Language:    m.Language,
		Image:       m.Image,
		Categories:  m.Categories,
		Tags:        m.Tags,
	}
	if !m.Date.IsZero() {
		d := m.Date
		out.Date = &d
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// truncateBytes returns s truncated to at most max bytes, never splitting a
// multibyte UTF-8 rune.  If truncation occurs, suffix is appended; otherwise
// s is returned unchanged with no suffix.  The byte budget is honoured
// strictly (body length before suffix is <= max): we walk back from the
// max-byte offset to the nearest rune boundary so the cut never lands inside
// an encoded rune, which would otherwise emit invalid UTF-8 into JSON
// metadata or rendered output.
func truncateBytes(s, suffix string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

func truncateField(s string, max int) string {
	s = strings.TrimSpace(s)
	return truncateBytes(s, "…", max)
}

// clampChars returns s cut to at most max bytes (never splitting a UTF-8
// rune) and reports whether a cut happened.  Unlike truncateBytes it appends
// no sentinel — extraction-cap truncation is signalled out-of-band via the
// returned flag so the pagination layer in fetch.go can phrase the notice
// with accurate offsets, and so the sentinel text never pollutes the cache.
// max <= 0 disables clamping (defensive: a Server built directly in tests
// may carry a zero-valued Config).
func clampChars(s string, max int) (string, bool) {
	if max <= 0 || len(s) <= max {
		return s, false
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

// ── Markdown renderer ─────────────────────────────────────────────────────────

// renderMarkdown walks an HTML node tree and emits structured markdown.
// Subtrees that are never article content (script, style, nav, footer) are
// skipped wholesale.  Output is capped at maxChars (Config.MaxExtractedChars
// in production); the boolean reports whether the cap cut anything, so the
// caller can surface "there was more" to the agent with accurate offsets.
//
// A nil root (e.g. trafilatura returned no content) yields an empty string.
//
// linkBase is the URL that relative hrefs are resolved against.  A nil
// linkBase disables link annotation entirely, which is how EXTRACT_LINKS=false
// is expressed to the renderer.
func renderMarkdown(root *html.Node, maxChars int, linkBase *url.URL) (string, bool) {
	if root == nil {
		return "", false
	}
	var sb bytes.Buffer

	type walkState struct {
		inPre        bool
		inCode       bool
		listDepth    int
		orderedStack []int
		headerRow    bool
		tableRow     []string
	}

	var walk func(*html.Node, walkState, int) walkState
	walk = func(n *html.Node, st walkState, depth int) walkState {
		if depth > maxDOMDepth {
			return st
		}
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)

			switch tag {
			case "script", "style", "noscript", "head", "nav", "footer":
				return st
			}

			switch tag {

			case "h1", "h2", "h3", "h4", "h5", "h6":
				level := int(tag[1] - '0')
				sb.WriteString("\n" + strings.Repeat("#", level) + " ")
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, st, depth+1)
				}
				sb.WriteString("\n")
				return st

			case "p":
				sb.WriteString("\n")
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, st, depth+1)
				}
				sb.WriteString("\n")
				return st

			case "blockquote":
				sb.WriteString("\n> ")
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, st, depth+1)
				}
				sb.WriteString("\n")
				return st

			case "pre":
				sb.WriteString("\n```\n")
				child := st
				child.inPre = true
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, child, depth+1)
				}
				sb.WriteString("\n```\n")
				return st

			case "code":
				if st.inPre {
					for c := n.FirstChild; c != nil; c = c.NextSibling {
						walk(c, st, depth+1)
					}
					return st
				}
				sb.WriteString("`")
				child := st
				child.inCode = true
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, child, depth+1)
				}
				sb.WriteString("`")
				return st

			case "ul":
				child := st
				child.listDepth++
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, child, depth+1)
				}
				if st.listDepth == 0 {
					sb.WriteString("\n")
				}
				return st

			case "ol":
				child := st
				child.listDepth++
				child.orderedStack = append(append([]int{}, st.orderedStack...), 0)
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					child = walk(c, child, depth+1)
				}
				if st.listDepth == 0 {
					sb.WriteString("\n")
				}
				return st

			case "li":
				// listDepth is incremented by the enclosing <ul>/<ol>, so a
				// well-formed item has listDepth >= 1.  An <li> with no list
				// ancestor leaves it at 0: html.Parse preserves stray list
				// items wherever they appear rather than synthesising a
				// wrapper, and real pages do emit them (e.g. inside a
				// <blockquote>).  Clamp to 0 — the item renders unindented at
				// top level — rather than handing strings.Repeat a negative
				// count, which panics and takes the whole server down.
				indentDepth := st.listDepth - 1
				if indentDepth < 0 {
					indentDepth = 0
				}
				indent := strings.Repeat("  ", indentDepth)
				if len(st.orderedStack) > 0 {
					idx := len(st.orderedStack) - 1
					st.orderedStack[idx]++
					_, _ = fmt.Fprintf(&sb, "\n%s%d. ", indent, st.orderedStack[idx])
				} else {
					_, _ = fmt.Fprintf(&sb, "\n%s- ", indent)
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, st, depth+1)
				}
				return st

			case "table":
				sb.WriteString("\n")
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, st, depth+1)
				}
				sb.WriteString("\n")
				return st

			case "thead":
				child := st
				child.headerRow = true
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, child, depth+1)
				}
				return st

			case "tbody", "tfoot":
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, st, depth+1)
				}
				return st

			case "tr":
				child := st
				child.tableRow = nil
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					child = walk(c, child, depth+1)
				}
				if len(child.tableRow) > 0 {
					sb.WriteString("| " + strings.Join(child.tableRow, " | ") + " |\n")
					if st.headerRow {
						seps := make([]string, len(child.tableRow))
						for i := range seps {
							seps[i] = "---"
						}
						sb.WriteString("| " + strings.Join(seps, " | ") + " |\n")
					}
				}
				return st

			case "th", "td":
				// Cells are collected by a separate mini-walk rather than the
				// main one, because everything in a cell has to end up on a
				// single line inside "| … |".  Fragments are gathered and
				// space-joined: concatenating raw text nodes would run
				// adjacent inline elements together ("Hello <em>world</em>"
				// → "Helloworld").
				//
				// Anchors are annotated here exactly as in the prose path.  A
				// table of references is the case where dropping targets
				// hurts most, so it gets the same treatment.
				// Fragments are kept raw until the final join so that link
				// labels (built from the fragments an <a> produced) are
				// escaped exactly once, by markdownLinkLabel.  Fragments
				// flagged literal are already-final markdown and are joined
				// untouched.
				type cellFrag struct {
					text    string
					literal bool
				}
				var frags []cellFrag
				var collect func(*html.Node)
				collect = func(cn *html.Node) {
					if cn.Type == html.TextNode {
						if t := strings.TrimSpace(cn.Data); t != "" {
							frags = append(frags, cellFrag{text: t})
						}
						return
					}
					if cn.Type == html.ElementNode && cn.Data == "a" && linkBase != nil {
						mark := len(frags)
						for c := cn.FirstChild; c != nil; c = c.NextSibling {
							collect(c)
						}
						href := resolveHref(cn, linkBase)
						if href == "" {
							return
						}
						parts := make([]string, 0, len(frags)-mark)
						for _, f := range frags[mark:] {
							parts = append(parts, f.text)
						}
						label := strings.Join(parts, " ")
						frags = frags[:mark]
						if label == "" || label == href {
							frags = append(frags,
								cellFrag{text: markdownSafeURL(href), literal: true})
							return
						}
						frags = append(frags, cellFrag{
							text:    "[" + markdownLinkLabel(label) + "](" + markdownSafeURL(href) + ")",
							literal: true,
						})
						return
					}
					for c := cn.FirstChild; c != nil; c = c.NextSibling {
						collect(c)
					}
				}
				collect(n)
				parts := make([]string, 0, len(frags))
				for _, f := range frags {
					if f.literal {
						parts = append(parts, f.text)
						continue
					}
					parts = append(parts, markdownCellText(f.text))
				}
				st.tableRow = append(st.tableRow, strings.Join(parts, " "))
				return st

			case "strong", "b":
				sb.WriteString("**")
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, st, depth+1)
				}
				sb.WriteString("**")
				return st

			case "em", "i":
				sb.WriteString("_")
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, st, depth+1)
				}
				sb.WriteString("_")
				return st

			case "a":
				start := sb.Len()
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, st, depth+1)
				}
				if linkBase == nil {
					return st
				}
				href := resolveHref(n, linkBase)
				if href == "" {
					return st
				}
				// sb.Bytes() is a view over the buffer; copy the slice to a
				// string before any further write can reallocate it.
				label := strings.TrimSpace(string(sb.Bytes()[start:]))
				switch {
				case label == "":
					// No visible anchor text (empty <a>, or one wrapping only
					// an image, which this renderer does not emit).  Injecting
					// a naked URL here would splice it into the middle of the
					// surrounding sentence, so emit nothing.
					return st
				case label == href:
					// The anchor text already IS the target — emit it once
					// rather than duplicating it as label and destination.
					sb.Truncate(start)
					sb.WriteString(markdownSafeURL(href))
				case strings.ContainsRune(label, '\n'):
					// The anchor wraps block-level content (card links, image
					// tiles, a heading inside an <a>).  Folding that into a
					// one-line markdown label would swallow the paragraph
					// breaks, so keep the block and append the target.
					if b := sb.Bytes(); len(b) > 0 && !isSpace(b[len(b)-1]) {
						sb.WriteByte(' ')
					}
					sb.WriteString("(" + markdownSafeURL(href) + ")")
				default:
					sb.Truncate(start)
					sb.WriteString("[" + markdownLinkLabel(label) + "](" + markdownSafeURL(href) + ")")
				}
				return st

			case "br":
				sb.WriteString("\n")

			case "div", "article", "section", "main", "header":
				sb.WriteString("\n")
			}
		}

		if n.Type == html.TextNode {
			text := n.Data
			if !st.inPre {
				hadLeading := len(text) > 0 && isSpace(text[0])
				hadTrailing := len(text) > 0 && isSpace(text[len(text)-1])
				parts := strings.Fields(text)
				if len(parts) == 0 {
					// Whitespace-only node.  It still carries meaning when it
					// separates two inline elements — dropping it entirely
					// welds them together ("<em>a</em> <em>b</em>" became
					// "_a__b_", and adjacent links became unreadable).  Emit
					// a single space unless the buffer already ends in
					// whitespace or nothing has been written yet.
					if b := sb.Bytes(); len(b) > 0 && !isSpace(b[len(b)-1]) {
						sb.WriteByte(' ')
					}
					goto children
				}
				text = strings.Join(parts, " ")
				if hadLeading {
					text = " " + text
				}
				if hadTrailing {
					text = text + " "
				}
			}
			sb.WriteString(text)
		}

	children:
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			st = walk(c, st, depth+1)
		}
		return st
	}

	walk(root, walkState{}, 0)

	lines := strings.Split(sb.String(), "\n")
	var out []string
	prevBlank := false
	for _, line := range lines {
		blank := strings.TrimSpace(line) == ""
		if blank && prevBlank {
			continue
		}
		out = append(out, line)
		prevBlank = blank
	}

	result := strings.TrimSpace(strings.Join(out, "\n"))
	return clampChars(result, maxChars)
}

// isSpace reports whether b is an ASCII whitespace byte.
func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// ── Link handling ─────────────────────────────────────────────────────────────

// resolveHref returns the absolute http(s) target of an <a> element, or ""
// when there is nothing worth surfacing.
//
// Rules, in order:
//   - no href, or an empty one            → ""
//   - a pure fragment ("#section")        → "" (same page; the fetch tool
//     ignores fragments as navigation targets, so it would be noise)
//   - unparseable                         → ""
//   - resolved against base, then any scheme other than http/https → ""
//
// The scheme allow-list is the load-bearing part.  javascript:, data:, and
// vbscript: hrefs are not fetchable by this server and are precisely how a
// hostile page would dress up an instruction to look like a navigable link.
// Fragments on otherwise-absolute URLs are preserved — they carry real
// citation value ("see §3") and cost nothing.
func resolveHref(n *html.Node, base *url.URL) string {
	var raw string
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, "href") {
			raw = strings.TrimSpace(a.Val)
			break
		}
	}
	if raw == "" || strings.HasPrefix(raw, "#") {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if base != nil {
		ref = base.ResolveReference(ref)
	}
	switch strings.ToLower(ref.Scheme) {
	case "http", "https":
	default:
		return ""
	}
	return ref.String()
}

// markdownLinkLabel flattens and escapes page-supplied anchor text so it
// cannot break out of the "[...]" of a markdown link, or out of the column
// it sits in.  Whitespace is collapsed (a label has to stay on one line);
// backslashes and square brackets are escaped so a label like "Report [2024]"
// or a trailing "\" cannot terminate the label early; and "|" is escaped
// because an unescaped one inside a table cell silently splits the row into
// extra columns.
func markdownLinkLabel(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "[", `\[`)
	s = strings.ReplaceAll(s, "]", `\]`)
	s = strings.ReplaceAll(s, "|", `\|`)
	return s
}

// markdownCellText escapes a plain (non-link) text fragment destined for a
// table cell.  Only "|" matters: an unescaped pipe in cell text splits the
// row into more columns than the header declares, which corrupts every
// subsequent column.  This is a pre-existing hazard the link work exposes
// more often, since reference tables are exactly where pipes show up.
func markdownCellText(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

// markdownSafeURL percent-encodes the characters that would otherwise
// terminate the structure containing the URL: parentheses close a markdown
// link destination, and "|" ends a table column.  url.URL.String() already
// encodes spaces and control characters, so these are the remainder.
//
// Both parens are encoded, not just the closing one, so the result stays
// balanced and legible rather than "Go_(name%29".  "|" is not a legal URI
// character under RFC 3986 at all, so %7C is the correct spelling rather
// than a substitution.  Parens are sub-delimiters, where percent-encoding is
// not universally a no-op — but they occur almost exclusively inside path
// segments (Wikipedia disambiguation suffixes being the common case) where
// servers treat the two forms identically, and the alternative is emitting a
// URL that is definitely truncated.
func markdownSafeURL(u string) string {
	u = strings.ReplaceAll(u, "(", "%28")
	u = strings.ReplaceAll(u, ")", "%29")
	return strings.ReplaceAll(u, "|", "%7C")
}
