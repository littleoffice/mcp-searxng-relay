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
