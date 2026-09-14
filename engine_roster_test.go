package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests pin the engine-roster contract: the operator-curated list is
// parsed from SEARXNG_ENGINES / SEARXNG_ENGINES_FILE, and it is what the search
// tool description advertises to the model. The roster exists to correct the
// "search box == Google" assumption that makes models emit site: filters, so a
// regression that dropped an engine or the dialect guidance would silently
// bring the bad behaviour back — the assertions have to live here.

func rosterNames(r []engineDescriptor) []string {
	names := make([]string, len(r))
	for i, e := range r {
		names[i] = e.Name
	}
	return names
}

func findEngine(r []engineDescriptor, name string) (engineDescriptor, bool) {
	for _, e := range r {
		if e.Name == name {
			return e, true
		}
	}
	return engineDescriptor{}, false
}

func TestParseEngineRoster_Inline(t *testing.T) {
	t.Setenv("SEARXNG_ENGINES", " Gitea: our self-hosted forge (repos, issues, code) ; wikipedia:encyclopedia ; nameonly ")
	t.Setenv("SEARXNG_ENGINES_FILE", "")

	roster, err := parseEngineRoster()
	if err != nil {
		t.Fatalf("parseEngineRoster returned error: %v", err)
	}

	if got, want := len(roster), 3; got != want {
		t.Fatalf("roster length = %d, want %d: %+v", got, want, roster)
	}
	// Order preserved as written.
	if got, want := strings.Join(rosterNames(roster), ","), "gitea,wikipedia,nameonly"; got != want {
		t.Errorf("roster names/order = %q, want %q", got, want)
	}
	// Name lowercased, purpose trimmed, colons inside the purpose survive.
	if e, _ := findEngine(roster, "gitea"); e.Purpose != "our self-hosted forge (repos, issues, code)" {
		t.Errorf("gitea purpose = %q", e.Purpose)
	}
	// A name-only entry keeps an empty purpose rather than being dropped.
	if e, ok := findEngine(roster, "nameonly"); !ok || e.Purpose != "" {
		t.Errorf("name-only entry = %+v, ok=%v", e, ok)
	}
}

func TestParseEngineRoster_PurposeKeepsColons(t *testing.T) {
	t.Setenv("SEARXNG_ENGINES", "docs: see https://example.invalid/help for details")
	t.Setenv("SEARXNG_ENGINES_FILE", "")

	roster, err := parseEngineRoster()
	if err != nil {
		t.Fatalf("parseEngineRoster returned error: %v", err)
	}
	e, ok := findEngine(roster, "docs")
	if !ok {
		t.Fatalf("docs engine missing: %+v", roster)
	}
	if want := "see https://example.invalid/help for details"; e.Purpose != want {
		t.Errorf("purpose = %q, want %q (only the first colon splits name from purpose)", e.Purpose, want)
	}
}

func TestParseEngineRoster_SkipsMalformed(t *testing.T) {
	// Leading/trailing separators, empty entries, and a bare ":" (empty name)
	// are skipped, not fatal — a stray separator must not block startup.
	t.Setenv("SEARXNG_ENGINES", ";; gitea: forge ; ; : orphan-purpose ;")
	t.Setenv("SEARXNG_ENGINES_FILE", "")

	roster, err := parseEngineRoster()
	if err != nil {
		t.Fatalf("parseEngineRoster returned error: %v", err)
	}
	if got, want := len(roster), 1; got != want {
		t.Fatalf("roster length = %d, want %d: %+v", got, want, roster)
	}
	if roster[0].Name != "gitea" {
		t.Errorf("survivor = %q, want gitea", roster[0].Name)
	}
}

func TestParseEngineRoster_Empty(t *testing.T) {
	t.Setenv("SEARXNG_ENGINES", "")
	t.Setenv("SEARXNG_ENGINES_FILE", "")

	roster, err := parseEngineRoster()
	if err != nil {
		t.Fatalf("parseEngineRoster returned error: %v", err)
	}
	if len(roster) != 0 {
		t.Errorf("expected empty roster, got %+v", roster)
	}
}

func TestParseEngineRoster_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engines.txt")
	content := "# curated engine roster\n" +
		"\n" +
		"gitea: self-hosted forge\n" +
		"  wikipedia : encyclopedia articles  \n" +
		"# a trailing comment\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp roster: %v", err)
	}

	t.Setenv("SEARXNG_ENGINES", "")
	t.Setenv("SEARXNG_ENGINES_FILE", path)

	roster, err := parseEngineRoster()
	if err != nil {
		t.Fatalf("parseEngineRoster returned error: %v", err)
	}
	if got, want := strings.Join(rosterNames(roster), ","), "gitea,wikipedia"; got != want {
		t.Fatalf("roster names = %q, want %q (comments and blanks ignored)", got, want)
	}
	if e, _ := findEngine(roster, "wikipedia"); e.Purpose != "encyclopedia articles" {
		t.Errorf("wikipedia purpose = %q, want trimmed value", e.Purpose)
	}
}

func TestParseEngineRoster_FileOverridesInline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engines.txt")
	if err := os.WriteFile(path, []byte("gitea: forge (detailed, from file)\ngithub: public GitHub\n"), 0o600); err != nil {
		t.Fatalf("write temp roster: %v", err)
	}

	t.Setenv("SEARXNG_ENGINES", "gitea: forge (from env)")
	t.Setenv("SEARXNG_ENGINES_FILE", path)

	roster, err := parseEngineRoster()
	if err != nil {
		t.Fatalf("parseEngineRoster returned error: %v", err)
	}
	// gitea appears once, at its original (inline) position, with the file's
	// purpose winning.
	if got, want := strings.Join(rosterNames(roster), ","), "gitea,github"; got != want {
		t.Fatalf("roster names = %q, want %q (override in place, no duplicate)", got, want)
	}
	if e, _ := findEngine(roster, "gitea"); e.Purpose != "forge (detailed, from file)" {
		t.Errorf("gitea purpose = %q, want the file value to win", e.Purpose)
	}
}

func TestParseEngineRoster_MissingFileIsFatal(t *testing.T) {
	t.Setenv("SEARXNG_ENGINES", "")
	t.Setenv("SEARXNG_ENGINES_FILE", filepath.Join(t.TempDir(), "does-not-exist.txt"))

	if _, err := parseEngineRoster(); err == nil {
		t.Fatal("expected an error for a named-but-unreadable SEARXNG_ENGINES_FILE, got nil")
	}
}

func TestBuildSearchToolDescription_NoRoster(t *testing.T) {
	desc := buildSearchToolDescription(nil)

	// The dialect guidance must be present even with zero configuration.
	for _, want := range []string{"SearXNG", "site:", "engines", "!bang"} {
		if !strings.Contains(desc, want) {
			t.Errorf("description missing %q with no roster:\n%s", want, desc)
		}
	}
	// With no roster there is nothing to advertise, so the engines block is
	// omitted.
	if strings.Contains(desc, "available on this instance") {
		t.Errorf("expected no engines block for an empty roster:\n%s", desc)
	}
	// The base description ships in the tool definitions on every request, so it
	// must stay terse. Guard against it regrowing toward the verbose original
	// (~750 bytes); the current text is ~260. The cap is deliberately loose —
	// it catches a paragraph creeping back in, not a few added words.
	if got, max := len(desc), 400; got > max {
		t.Errorf("empty-roster description is %d bytes, want <= %d (keep the always-on tool prefix terse):\n%s", got, max, desc)
	}
}

func TestBuildSearchToolDescription_WithRoster(t *testing.T) {
	roster := []engineDescriptor{
		{Name: "gitea", Purpose: "self-hosted forge (repos, issues, code)"},
		{Name: "wikipedia"}, // name-only
	}
	desc := buildSearchToolDescription(roster)

	if !strings.Contains(desc, "available on this instance") {
		t.Errorf("expected an engines block for a populated roster:\n%s", desc)
	}
	if !strings.Contains(desc, "gitea") || !strings.Contains(desc, "self-hosted forge (repos, issues, code)") {
		t.Errorf("description missing gitea entry or its purpose:\n%s", desc)
	}
	// A name-only engine still appears so the model knows it exists.
	if !strings.Contains(desc, "wikipedia") {
		t.Errorf("description missing name-only engine:\n%s", desc)
	}
	// The dialect guidance is retained alongside the roster.
	if !strings.Contains(desc, "site:") {
		t.Errorf("dialect guidance dropped when a roster is present:\n%s", desc)
	}
}
