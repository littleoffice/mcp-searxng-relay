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

// maxRenderedChars is the upper bound on rendered markdown returned to the
// agent.  Pages beyond this are truncated with a sentinel rather than
// dropped, because partial content is usually more useful than none.
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
func extractHTMLDocument(body []byte, originalURL string) (*html.Node, URLMetadata, error) {
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

// ── Markdown renderer ─────────────────────────────────────────────────────────

// renderMarkdown walks an HTML node tree and emits structured markdown.
// Subtrees that are never article content (script, style, nav, footer) are
// skipped wholesale.  Output is capped at maxRenderedChars with a sentinel
// rather than dropped — partial content is more useful than none.
//
// A nil root (e.g. trafilatura returned no content) yields an empty string.
func renderMarkdown(root *html.Node) string {
	if root == nil {
		return ""
	}
	var sb strings.Builder

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
				indent := strings.Repeat("  ", st.listDepth-1)
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
				var cell strings.Builder
				var collectText func(*html.Node)
				collectText = func(cn *html.Node) {
					if cn.Type == html.TextNode {
						cell.WriteString(strings.TrimSpace(cn.Data))
					}
					for c := cn.FirstChild; c != nil; c = c.NextSibling {
						collectText(c)
					}
				}
				collectText(n)
				st.tableRow = append(st.tableRow, strings.TrimSpace(cell.String()))
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
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, st, depth+1)
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
	return truncateBytes(result, "\n\n[content truncated]", maxRenderedChars)
}

// isSpace reports whether b is an ASCII whitespace byte.
func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
