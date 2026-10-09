package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

// ── Hidden-element removal ────────────────────────────────────────────────────
//
// A page can carry text the person reading it never sees: an element marked
// hidden, a <template>, an inline style that collapses it to nothing.  A
// browser skips it; an extractor does not, so without this step the model
// reads instructions the user had no chance to notice.
//
// stripHiddenElements removes those elements BEFORE trafilatura sees the
// document.  Filtering in renderMarkdown would be too late: trafilatura and
// its readability / dom-distiller fallbacks choose the article subtree (and
// may copy text out of it) first, and every one of them works on the
// document handed to Extract.  Cleaning that one document is the only place
// where no extraction path can route around the filter.
//
// What counts as hidden, deliberately limited to what is decidable from the
// element itself:
//
//   - the `hidden` attribute (except hidden="until-found", which the browser
//     reveals on find-in-page and on fragment navigation — the same class as
//     a collapsed <details>, which is kept too);
//   - aria-hidden="true";
//   - <template> (its content is inert until script clones it);
//   - <input type="hidden">;
//   - an inline style declaring display:none, visibility:hidden|collapse,
//     opacity:0 or font-size:0, parsed tolerantly (see inlineStyleHides).
//
// Hiding done through a stylesheet or a class name cannot be detected without
// a full CSS engine and is out of scope; the README says so.
//
// FETCH_KEEP_HIDDEN_TEXT=true turns it off.

// stripHiddenElements returns body with every hidden element (and its whole
// subtree) removed, and how many elements it removed.  A count of zero
// returns body itself, byte for byte, so pages with nothing hidden reach the
// extractor exactly as before.
//
// A render failure is returned as an error rather than falling back to the
// original body: the fallback would hand the extractor the very text this
// function exists to remove.
func stripHiddenElements(body []byte) ([]byte, int, error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("parse for hidden-element removal: %w", err)
	}
	removed := removeHiddenNodes(doc)
	if removed == 0 {
		return body, 0, nil
	}
	var buf bytes.Buffer
	buf.Grow(len(body))
	if err := html.Render(&buf, doc); err != nil {
		return nil, 0, fmt.Errorf("render after hidden-element removal: %w", err)
	}
	return buf.Bytes(), removed, nil
}

// removeHiddenNodes detaches every hidden element under root and returns how
// many it detached.  Descendants of a removed element are not counted
// separately: one hidden <div> holding twenty paragraphs is one hiding act.
//
// The walk uses an explicit stack rather than recursion.  html.Parse keeps
// whatever nesting a page ships, and a filter that gave up past some depth
// would let anything nested deeper than that through untouched.
func removeHiddenNodes(root *html.Node) int {
	removed := 0
	stack := []*html.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for c := n.FirstChild; c != nil; {
			next := c.NextSibling
			if c.Type == html.ElementNode && isHiddenElement(c) {
				n.RemoveChild(c)
				removed++
			} else {
				stack = append(stack, c)
			}
			c = next
		}
	}
	return removed
}

// isHiddenElement reports whether a browser would render n as nothing,
// judging only by n's own tag and attributes.
func isHiddenElement(n *html.Node) bool {
	tag := strings.ToLower(n.Data)
	if tag == "template" {
		return true
	}
	for _, a := range n.Attr {
		key := strings.ToLower(a.Key)
		val := strings.ToLower(strings.TrimSpace(a.Val))
		switch key {
		case "hidden":
			if val != "until-found" {
				return true
			}
		case "aria-hidden":
			if val == "true" {
				return true
			}
		case "type":
			if tag == "input" && val == "hidden" {
				return true
			}
		case "style":
			if inlineStyleHides(a.Val) {
				return true
			}
		}
	}
	return false
}

// inlineStyleHides reports whether a style attribute's declarations hide the
// element.  It is tolerant of what real pages (and hostile ones) write:
// arbitrary whitespace and case, comments, a trailing or missing semicolon,
// `!important`, and zero written as 0, 0.0, 0px, 0em, 0% and the like.
//
// Declarations are resolved the way the cascade resolves them within one
// style attribute: the last declaration of a property wins, except that a
// normal declaration cannot override an earlier !important one.  So
// "display:none !important; display:block" hides, and
// "display:none; display:block" does not.
func inlineStyleHides(style string) bool {
	type decl struct {
		value     string
		important bool
	}
	final := map[string]decl{}
	for _, part := range strings.Split(stripCSSComments(style), ";") {
		prop, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		prop = strings.ToLower(strings.TrimSpace(prop))
		value = strings.ToLower(strings.TrimSpace(value))
		important := false
		if i := strings.LastIndexByte(value, '!'); i >= 0 &&
			strings.TrimSpace(value[i+1:]) == "important" {
			important = true
			value = strings.TrimSpace(value[:i])
		}
		if prev, seen := final[prop]; seen && prev.important && !important {
			continue
		}
		final[prop] = decl{value: value, important: important}
	}

	switch final["display"].value {
	case "none":
		return true
	}
	switch final["visibility"].value {
	case "hidden", "collapse":
		return true
	}
	if d, ok := final["opacity"]; ok && isCSSZero(d.value) {
		return true
	}
	if d, ok := final["font-size"]; ok && isCSSZero(d.value) {
		return true
	}
	return false
}

// stripCSSComments removes /* … */ comments, which may sit anywhere in a
// declaration ("display:/**/none").  An unterminated comment swallows the
// rest of the string, as it does in CSS.
func stripCSSComments(s string) string {
	for {
		i := strings.Index(s, "/*")
		if i < 0 {
			return s
		}
		j := strings.Index(s[i+2:], "*/")
		if j < 0 {
			return s[:i]
		}
		s = s[:i] + s[i+2+j+2:]
	}
}

// isCSSZero reports whether v is a numeric zero with an optional unit or
// percent sign: "0", "0.0", ".0", "-0", "0px", "0em", "0%".  Anything else —
// a keyword, calc(), a non-zero number — is not zero.
func isCSSZero(v string) bool {
	num := strings.TrimRightFunc(v, func(r rune) bool {
		return (r >= 'a' && r <= 'z') || r == '%'
	})
	if num == "" {
		return false
	}
	f, err := strconv.ParseFloat(num, 64)
	return err == nil && f == 0
}
