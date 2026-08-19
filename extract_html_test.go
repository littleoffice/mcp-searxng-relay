package main

import (
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// renderString is a test helper: parse HTML, render it, return the markdown.
// linkBase is nil throughout — these cases are about block structure, and
// link annotation would only add noise to the expected strings.
func renderString(t *testing.T, src string) string {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("html.Parse(%q): %v", src, err)
	}
	out, _ := renderMarkdown(doc, 1_000_000, nil)
	return out
}

// A list item whose ancestors contain no <ul>/<ol> used to crash the process.
// The renderer derives its indent from listDepth-1, listDepth is incremented
// only by a list element, and strings.Repeat panics on a negative count — so a
// stray <li> took down the whole server, not just the one request, because the
// panic happened on a per-URL goroutine spawned by the metadata tool.
//
// Stray items are not a malformed-input curiosity: html.Parse preserves an
// <li> wherever it appears rather than synthesising a list wrapper, and real
// pages ship them (the report that prompted this test was a blog post with an
// <li> directly inside a <blockquote>).  Any fetched page is untrusted input,
// so the renderer has to survive every shape the parser can hand it.
func TestRenderMarkdown_StrayListItemDoesNotPanic(t *testing.T) {
	cases := map[string]struct{ html, want string }{
		"inside blockquote": {"<blockquote><li>stray</li></blockquote>", "- stray"},
		"bare in body":      {"<li>orphan</li>", "- orphan"},
		"inside div":        {"<div><li>orphan</li></div>", "- orphan"},
		"after a real list": {"<ul><li>real</li></ul><blockquote><li>stray</li></blockquote>", "- stray"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// A panic here fails the test rather than the process; the
			// assertion below is what pins the chosen recovery behaviour.
			got := renderString(t, tc.html)
			if !strings.Contains(got, tc.want) {
				t.Errorf("stray <li> rendered as %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

// The indent clamp must not flatten genuine nesting: an item's indent still
// has to track how many lists enclose it, and ordered lists still have to
// number independently per level.  Pinned because the obvious fix for the
// panic above — dropping the indent entirely — would pass that test while
// silently destroying the structure of every nested list on every page.
func TestRenderMarkdown_ListNesting(t *testing.T) {
	cases := map[string]struct{ html, want string }{
		"flat unordered": {
			"<ul><li>a</li><li>b</li></ul>",
			"- a\n- b",
		},
		"nested unordered": {
			"<ul><li>a<ul><li>a1</li></ul></li><li>b</li></ul>",
			"- a\n  - a1\n- b",
		},
		"ordered numbering": {
			"<ol><li>one</li><li>two</li><li>three</li></ol>",
			"1. one\n2. two\n3. three",
		},
		"nested ordered restarts": {
			"<ol><li>one<ol><li>sub</li></ol></li><li>two</li></ol>",
			"1. one\n  1. sub\n2. two",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := renderString(t, tc.html)
			if !strings.Contains(got, tc.want) {
				t.Errorf("rendered %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

// Ordinary nested cell content must still render: the depth guard on the
// table-cell mini-walk must not flatten or drop legitimately nested inline
// markup, only the pathological far end of it.
func TestRenderMarkdown_NestedCellRenders(t *testing.T) {
	got := renderString(t, "<table><tr><td><span><b>deep cell text</b></span></td></tr></table>")
	if !strings.Contains(got, "deep cell text") {
		t.Errorf("nested cell rendered as %q, want it to contain %q", got, "deep cell text")
	}
}

// The main renderer walk is depth-capped (maxDOMDepth) so adversarial nesting
// cannot exhaust the goroutine stack — a fatal, unrecoverable crash rather than
// a catchable panic. The separate <td>/<th> cell mini-walk must carry the same
// cap: today x/net/html's parser refuses to build a tree deeper than 512 open
// elements, which keeps the cell walk bounded in practice, but the renderer
// should not depend on that parser limit staying put — the guard belongs in the
// walk itself, matching the main path.
//
// The tree is built directly rather than via html.Parse precisely because the
// parser's 512-node cap would otherwise reject a past-maxDOMDepth document, so
// only a hand-built node tree can pin the renderer's own guarantee. The
// assertion pins the shared budget: content shallower than the cap survives,
// content past it is cut, and the render returns instead of recursing without
// limit.
func TestRenderMarkdown_DeeplyNestedCellIsBounded(t *testing.T) {
	td := &html.Node{Type: html.ElementNode, Data: "td"}
	// A direct text child sits within the cap and must always be collected.
	td.AppendChild(&html.Node{Type: html.TextNode, Data: "shallow"})
	// A chain of spans far deeper than maxDOMDepth, ending in a marker the
	// guard must never reach.
	cur := td
	for i := 0; i < maxDOMDepth*2; i++ {
		span := &html.Node{Type: html.ElementNode, Data: "span"}
		cur.AppendChild(span)
		cur = span
	}
	cur.AppendChild(&html.Node{Type: html.TextNode, Data: "marker"})

	tr := &html.Node{Type: html.ElementNode, Data: "tr"}
	tr.AppendChild(td)
	table := &html.Node{Type: html.ElementNode, Data: "table"}
	table.AppendChild(tr)

	got, _ := renderMarkdown(table, 1_000_000, nil)

	if !strings.Contains(got, "shallow") {
		t.Errorf("cell text above the depth cap was dropped; got %q", got)
	}
	if strings.Contains(got, "marker") {
		t.Error("cell content nested past maxDOMDepth was rendered; the depth guard did not fire")
	}
}
