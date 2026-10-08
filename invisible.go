package main

import (
	"strings"
	"unicode/utf8"
)

// ── Invisible-character removal ───────────────────────────────────────────────
//
// Fetched text can carry instructions a person reading the page never sees but
// a model reads in full.  Three character classes do this without any markup
// at all, so nothing in the HTML pipeline catches them:
//
//   - Unicode tag characters, U+E0000–U+E007F.  They mirror ASCII one for one
//     and render as nothing, so a run of them spells a whole sentence that is
//     invisible in a browser, an editor and a terminal alike.
//   - Zero-width characters: U+200B–U+200D, U+2060–U+2064, U+FEFF.  Used to
//     split trigger words past filters or to hide a payload between visible
//     letters.
//   - Bidi controls, U+202A–U+202E and U+2066–U+2069.  They reorder what a
//     person sees without changing what a model reads, so displayed text and
//     tokenised text disagree.
//
// stripInvisible removes all three, with two exceptions that keep ordinary
// emoji intact: a ZERO WIDTH JOINER between two emoji (family, profession and
// flag sequences), and the tag sequence that encodes a subdivision flag
// (England, Scotland, Wales).
//
// It runs on every piece of fetched text before that text is cached, fenced
// and signed — never on URLs, which must stay byte-exact.  The count it
// returns feeds the awareness preamble (see sanitisationNote), the
// mcp_invisible_chars_removed_total counter and a log line, so a removal is
// never silent.
//
// FETCH_KEEP_INVISIBLE_CHARS=true turns it off.

const (
	tagBlockFirst = 0xE0000
	tagBlockLast  = 0xE007F
	// cancelTag terminates a tag sequence.
	cancelTag = 0xE007F
	// blackFlag is the only base a subdivision-flag tag sequence may follow
	// (UTS #51, emoji_tag_sequence).
	blackFlag = 0x1F3F4
	// maxSubdivisionTags bounds the tag-spec part of a subdivision flag.  Real
	// ones use five ("gbeng"); six leaves room for the longest code the
	// standard allows.  A longer run is a payload dressed as a flag.
	maxSubdivisionTags = 6
	zeroWidthJoiner    = 0x200D
)

// isInvisibleRune reports whether r is in one of the removed classes,
// ignoring the context-dependent exceptions.
func isInvisibleRune(r rune) bool {
	switch {
	case r >= tagBlockFirst && r <= tagBlockLast:
		return true
	case r >= 0x200B && r <= 0x200D: // ZWSP, ZWNJ, ZWJ
		return true
	case r >= 0x2060 && r <= 0x2064: // WORD JOINER … INVISIBLE PLUS
		return true
	case r == 0xFEFF: // ZERO WIDTH NO-BREAK SPACE / BOM
		return true
	case r >= 0x202A && r <= 0x202E: // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	}
	return false
}

// isSubdivisionTag reports whether r may appear in the tag-spec part of a
// subdivision flag: TAG DIGIT ZERO–NINE or TAG LATIN SMALL LETTER A–Z.
func isSubdivisionTag(r rune) bool {
	return (r >= 0xE0030 && r <= 0xE0039) || (r >= 0xE0061 && r <= 0xE007A)
}

// isEmojiRune is a deliberately broad approximation of Extended_Pictographic
// plus the emoji modifiers and regional indicators.  It decides only whether a
// ZERO WIDTH JOINER is kept, so erring wide costs at most one invisible joiner
// between two symbols; erring narrow would split a family emoji into its
// members.  A table-exact check would need a Unicode-data dependency for no
// security gain.
func isEmojiRune(r rune) bool {
	switch {
	case r == 0x00A9, r == 0x00AE, r == 0x203C, r == 0x2049, r == 0x2122, r == 0x2139:
		return true
	case r >= 0x2194 && r <= 0x21AA:
		return true
	case r >= 0x231A && r <= 0x23FF:
		return true
	case r >= 0x24C2 && r <= 0x25FE:
		return true
	case r >= 0x2600 && r <= 0x27BF:
		return true
	case r >= 0x2934 && r <= 0x2935:
		return true
	case r >= 0x2B05 && r <= 0x2B55:
		return true
	case r == 0x3030, r == 0x303D, r == 0x3297, r == 0x3299:
		return true
	case r >= 0x1F000 && r <= 0x1FAFF:
		return true
	case r >= 0x1FC00 && r <= 0x1FFFD:
		return true
	}
	return false
}

// isEmojiPresentationSelector covers the variation selectors that may sit
// between an emoji and a following joiner (HEART ON FIRE is U+2764 U+FE0F
// U+200D U+1F525).  They are skipped when looking back for the joiner's left side.
func isEmojiPresentationSelector(r rune) bool {
	return r == 0xFE0E || r == 0xFE0F
}

// stripInvisible returns s with invisible characters removed, and how many
// runes it removed.  Text with none of them is returned unchanged without
// allocating.
func stripInvisible(s string) (string, int) {
	if !containsInvisible(s) {
		return s, 0
	}

	var sb strings.Builder
	sb.Grow(len(s))
	removed := 0
	// prev is the last rune written, for the ZWJ left-side check.  Only
	// written runes count: a joiner after something that was itself removed
	// joins nothing visible.
	var prev rune = -1

	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])

		if r == blackFlag {
			sb.WriteRune(r)
			prev = r
			i += size
			// Consume the whole tag run that follows, keeping it only if it
			// is exactly a well-formed subdivision flag.
			j, tags, ok := scanTagRun(s, i)
			if ok {
				sb.WriteString(s[i:j])
			} else {
				removed += tags
			}
			i = j
			continue
		}

		if r == zeroWidthJoiner {
			left := prev
			next, _ := utf8.DecodeRuneInString(s[i+size:])
			if left >= 0 && isEmojiRune(left) && isEmojiRune(next) {
				sb.WriteRune(r)
				prev = r
			} else {
				removed++
			}
			i += size
			continue
		}

		if isInvisibleRune(r) {
			removed++
			i += size
			continue
		}

		sb.WriteRune(r)
		if !isEmojiPresentationSelector(r) {
			prev = r
		}
		i += size
	}
	return sb.String(), removed
}

// scanTagRun reads the run of tag-block runes starting at s[i:] and returns
// the index just past it, how many runes it held, and whether it is a valid
// subdivision-flag tail: 1–maxSubdivisionTags spec tags followed by CANCEL
// TAG, and nothing else.
func scanTagRun(s string, i int) (end, count int, ok bool) {
	end = i
	spec := 0
	cancelled := false
	ok = true
	for end < len(s) {
		r, size := utf8.DecodeRuneInString(s[end:])
		if r < tagBlockFirst || r > tagBlockLast {
			break
		}
		count++
		end += size
		switch {
		case cancelled:
			// Anything after the terminator belongs to no flag.
			ok = false
		case r == cancelTag:
			cancelled = true
		case isSubdivisionTag(r):
			spec++
		default:
			ok = false
		}
	}
	if count == 0 {
		return end, 0, true
	}
	ok = ok && cancelled && spec >= 1 && spec <= maxSubdivisionTags
	return end, count, ok
}

// containsInvisible is the fast path: one pass over the runes with no
// allocation, so the common case of clean text costs a scan and nothing more.
func containsInvisible(s string) bool {
	for _, r := range s {
		if isInvisibleRune(r) {
			return true
		}
	}
	return false
}

// stripInvisibleMetadata sanitises the page-supplied text fields of m in
// place and returns how many runes it removed.  URL and Image are URLs and are
// left byte-exact; Date and PageCount are not text.
func stripInvisibleMetadata(m *URLMetadata) int {
	total := 0
	strip := func(p *string) {
		var n int
		*p, n = stripInvisible(*p)
		total += n
	}
	strip(&m.Title)
	strip(&m.Author)
	strip(&m.Description)
	strip(&m.SiteName)
	strip(&m.Language)
	for i := range m.Categories {
		strip(&m.Categories[i])
	}
	for i := range m.Tags {
		strip(&m.Tags[i])
	}
	return total
}
