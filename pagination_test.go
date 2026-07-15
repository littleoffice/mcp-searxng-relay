package main

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// These tests pin the pagination contract described on paginateContent:
// exact continuation offsets, rune-boundary safety, guaranteed forward
// progress, and the conditions under which each notice appears. The
// contract is part of the tool's response format — agents parse the
// continuation hint — so changes here are breaking changes for callers.

func TestPaginate_ShortContentPassesThrough(t *testing.T) {
	text := "hello world"
	out, start, end, err := paginateContent(text, 0, 0, false, 1_000_000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != text {
		t.Errorf("short content must pass through unmodified; got %q", out)
	}
	if start != 0 || end != len(text) {
		t.Errorf("expected window [0,%d), got [%d,%d)", len(text), start, end)
	}
}

func TestPaginate_ContinuationHintRoundTrips(t *testing.T) {
	// Content longer than one window; walk it page by page using only the
	// offsets a real agent would echo back, and verify the reassembled
	// body matches the original with no gaps or overlaps.
	text := strings.Repeat("abcdefghij", 25) // 250 chars
	const window = 100

	var rebuilt strings.Builder
	start := 0
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
		out, gotStart, gotEnd, err := paginateContent(text, start, window, false, 1_000_000)
		if err != nil {
			t.Fatalf("page at start=%d: %v", start, err)
		}
		if gotStart != start {
			t.Errorf("echoed start_index %d came back as %d", start, gotStart)
		}
		// The body is everything before the notice block (if any).
		body, _, _ := strings.Cut(out, "\n\n[")
		rebuilt.WriteString(body)
		if gotEnd == len(text) {
			if strings.Contains(out, "start_index=") {
				t.Errorf("final page must not carry a continuation hint; got %q", out)
			}
			break
		}
		want := fmt.Sprintf("start_index=%d", gotEnd)
		if !strings.Contains(out, want) {
			t.Fatalf("expected continuation hint %q in %q", want, out)
		}
		start = gotEnd
	}
	if rebuilt.String() != text {
		t.Errorf("reassembled pages differ from original: got %d chars, want %d",
			rebuilt.Len(), len(text))
	}
}

func TestPaginate_NeverSplitsRunes(t *testing.T) {
	// 3-byte runes with a window size that always lands mid-rune.
	text := strings.Repeat("日本語", 50) // 450 bytes
	start := 0
	for i := 0; i < 20 && start < len(text); i++ {
		out, gotStart, gotEnd, err := paginateContent(text, start, 100, false, 1_000_000)
		if err != nil {
			t.Fatalf("page at start=%d: %v", start, err)
		}
		body, _, _ := strings.Cut(out, "\n\n[")
		if !utf8.ValidString(body) {
			t.Fatalf("window [%d,%d) emitted invalid UTF-8", gotStart, gotEnd)
		}
		if gotEnd == len(text) {
			return
		}
		start = gotEnd
	}
	t.Fatal("did not reach end of content")
}

func TestPaginate_MidRuneStartIndexSnapsBack(t *testing.T) {
	// An invented (non-echoed) start_index landing inside an encoded rune
	// must snap to a boundary rather than emit invalid UTF-8.
	text := strings.Repeat("日", 100) // 300 bytes
	out, start, _, err := paginateContent(text, 4, 0, false, 1_000_000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if start != 3 {
		t.Errorf("start_index=4 inside a 3-byte rune should snap back to 3, got %d", start)
	}
	if !utf8.ValidString(out) {
		t.Error("snapped window emitted invalid UTF-8")
	}
}

func TestPaginate_ForwardProgressOnTinyWindow(t *testing.T) {
	// max_chars smaller than the first rune must still advance: a window
	// that returns end == start would make an agent that echoes the hint
	// loop forever.
	text := strings.Repeat("日", 10)
	_, start, end, err := paginateContent(text, 0, 1, false, 1_000_000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if end <= start {
		t.Fatalf("window [%d,%d) makes no forward progress", start, end)
	}
}

func TestPaginate_StartBeyondEndIsRecoverableError(t *testing.T) {
	_, _, _, err := paginateContent("short", 100, 0, false, 1_000_000)
	if err == nil {
		t.Fatal("expected an error for start_index beyond end of content")
	}
	// The total must be in the message so the agent can recover without
	// guessing.
	if !strings.Contains(err.Error(), "5 chars total") {
		t.Errorf("error should include the total content size: %v", err)
	}
}

func TestPaginate_EndOfContentNoteOnlyForNonZeroStart(t *testing.T) {
	text := strings.Repeat("x", 150)
	out, _, _, err := paginateContent(text, 100, 100, false, 1_000_000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "end of content") {
		t.Errorf("final page after a non-zero start should carry an end-of-content note; got %q", out)
	}
}

func TestPaginate_ExtractionCapNoteOnlyAtEnd(t *testing.T) {
	text := strings.Repeat("x", 250)

	// Window that does NOT reach the end: cap note must be absent, even
	// though extraction was truncated — the agent can't act on it yet.
	out, _, _, err := paginateContent(text, 0, 100, true, 1_000_000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(out, "extraction cap") {
		t.Errorf("extraction-cap note must not appear before the window reaches the end; got %q", out)
	}

	// Window that reaches the end: note must be present.
	out, _, _, err = paginateContent(text, 200, 100, true, 1_000_000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "extraction cap") {
		t.Errorf("extraction-cap note missing on final window; got %q", out)
	}
}

func TestPaginate_OversizeAndNonPositiveMaxCharsClampToDefault(t *testing.T) {
	text := strings.Repeat("x", maxRenderedChars+500)
	for _, maxChars := range []int{0, -5, maxRenderedChars * 10} {
		_, start, end, err := paginateContent(text, 0, maxChars, false, 0)
		if err != nil {
			t.Fatalf("max_chars=%d: unexpected error: %v", maxChars, err)
		}
		if got := end - start; got != maxRenderedChars {
			t.Errorf("max_chars=%d: window size %d, want the %d default/ceiling",
				maxChars, got, maxRenderedChars)
		}
	}
}

func TestClampChars(t *testing.T) {
	// No clamp cases.
	for _, tc := range []struct {
		s   string
		max int
	}{
		{"hello", 10},
		{"hello", 5},
		// max <= 0 disables clamping (a Server built directly in tests
		// carries a zero-valued Config).
		{"anything", 0},
		{"anything", -1},
	} {
		out, truncated := clampChars(tc.s, tc.max)
		if out != tc.s || truncated {
			t.Errorf("clampChars(%q, %d) = (%q, %v), want unchanged", tc.s, tc.max, out, truncated)
		}
	}

	// Clamp respects rune boundaries: cutting "日" (3 bytes) at 4 must not
	// leave a partial second rune.
	out, truncated := clampChars("日日", 4)
	if !truncated {
		t.Error("expected truncation")
	}
	if out != "日" {
		t.Errorf("clampChars mid-rune: got %q, want %q", out, "日")
	}
	if !utf8.ValidString(out) {
		t.Error("clamped output is invalid UTF-8")
	}
}

// The PDF page-marker format is part of the tool's response contract: the
// read tool's description tells agents to look for these exact lines, so
// changes to the format are breaking changes for callers.  extractPDF
// itself needs the native pdf_oxide library and a fixture document, so
// only the pure marker helper is pinned here; the assembly loop is
// exercised by integration use.
func TestPDFPageMarkerFormat(t *testing.T) {
	got := pdfPageMarker(3, 348)
	want := "--- [PDF page 3 of 348] ---"
	if got != want {
		t.Errorf("pdfPageMarker(3, 348) = %q, want %q", got, want)
	}
}

// Markers must survive pagination intact: a window boundary that lands
// inside a marker line would strand the agent mid-anchor.  This does not
// require boundary avoidance — only that following continuation hints
// reassembles every marker byte-for-byte, which the round-trip guarantee
// already provides.  Pinned separately because marker navigation is the
// feature agents actually depend on.
func TestPaginate_PageMarkersSurviveWindowing(t *testing.T) {
	var doc strings.Builder
	for p := 1; p <= 9; p++ {
		if p > 1 {
			doc.WriteString("\n\n")
		}
		doc.WriteString(pdfPageMarker(p, 9))
		doc.WriteString("\n\n")
		doc.WriteString(strings.Repeat("content ", 10))
	}
	text := doc.String()

	var rebuilt strings.Builder
	start := 0
	for i := 0; i < 50; i++ {
		out, _, end, err := paginateContent(text, start, 100, false, 1_000_000)
		if err != nil {
			t.Fatalf("page at start=%d: %v", start, err)
		}
		body, _, _ := strings.Cut(out, "\n\n[")
		rebuilt.WriteString(body)
		if end == len(text) {
			break
		}
		start = end
	}
	for p := 1; p <= 9; p++ {
		if !strings.Contains(rebuilt.String(), pdfPageMarker(p, 9)) {
			t.Errorf("marker for page %d lost during windowing round-trip", p)
		}
	}
}
