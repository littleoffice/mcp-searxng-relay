#!/usr/bin/env bash
# check-doc-pins.sh — check that docs/supply-chain.md agrees with go.mod about
# which dependency versions this project builds against.
#
# Usage:
#   ./check-doc-pins.sh            # check, print a report, exit non-zero on drift
#   ./check-doc-pins.sh --fix      # rewrite the stale numbers in place
#
# Exit codes: 0 in agreement, 1 drift found, 64 usage error.
#
# WHY THIS EXISTS
#
# Dependabot bumps go.mod. It does not know that docs/supply-chain.md names the
# same versions in prose, so every bump silently widens a gap between the two.
# That gap grew to six of ten table rows and two build-step notes before anyone
# noticed, one of them trailing the real pin by seventeen patch releases.
#
# Nothing breaks when that happens, which is exactly the problem: a
# supply-chain document whose numbers are visibly months stale is one a
# reviewer stops checking against, and its value is entirely in being
# checkable. This is the same invariant class .github/workflows/pin-consistency
# .yml already guards between the Dockerfile and the go.mod `go` directive —
# something Dependabot cannot maintain on its own, so CI holds it instead.
#
# It is a script rather than lines inlined in the workflow for the reason
# verify-native-dep.sh is: the check runs in CI and in front of a contributor
# editing go.mod, and two copies of it would drift.
#
# WHAT IT CHECKS
#
#   1. Every direct dependency in go.mod has a row in the inventory table.
#   2. Every table row names the version go.mod pins.
#   3. The "**N direct dependencies**" count matches how many go.mod declares.
#   4. The two "derived from go.mod at build time (currently vX)" notes in the
#      build-step sections name the version go.mod pins.
#
# It deliberately does NOT check transitive versions. go.sum is authoritative
# there, the document discusses them as families rather than pins, and a check
# over prose that loose would fail on wording rather than on drift.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gomod="${here}/go.mod"
doc="${here}/docs/supply-chain.md"

fix=0
case "${1:-}" in
	--fix) fix=1 ;;
	"") ;;
	-h | --help)
		sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "check-doc-pins: unknown argument '${1}'" >&2
		echo "usage: ./check-doc-pins.sh [--fix]" >&2
		exit 64
		;;
esac

for f in "${gomod}" "${doc}"; do
	[ -r "${f}" ] || {
		echo "check-doc-pins: cannot read ${f}" >&2
		exit 64
	}
done

# Direct dependencies: the require entries that are not marked `// indirect`.
# Parsed out of go.mod rather than read via `go list -m`, so the check needs no
# module cache, no network, and no toolchain — it runs the same in CI, in a
# pre-commit hook, and in a container that has never fetched a module.
#
# Handles both the block form and single-line `require path version`.
direct="$(awk '
	/^require[[:space:]]*\(/ { block = 1; next }
	block && /^\)/           { block = 0; next }
	/\/\/[[:space:]]*indirect/ { next }
	block && NF >= 2         { print $1, $2; next }
	/^require[[:space:]]+[^([:space:]]+[[:space:]]+v/ { print $2, $3 }
' "${gomod}")"

[ -n "${direct}" ] || {
	echo "check-doc-pins: found no direct dependencies in ${gomod} — refusing to pass vacuously" >&2
	exit 64
}

drift=0
report=""

note() { report="${report}${1}"$'\n'; }

# GitHub renders ::error annotations against the file; locally they are just
# a readable prefix, so the same output serves both.
fail() {
	drift=1
	note "  DRIFT  ${1}"
	echo "::error file=docs/supply-chain.md::${2}"
}

# ---------------------------------------------------------------------------
# 1 + 2: a row per direct dependency, naming the version go.mod pins.
# ---------------------------------------------------------------------------
count=0
while read -r path version; do
	[ -n "${path}" ] || continue
	count=$((count + 1))

	# The row for this module: a table line whose first cell is the module
	# path in backticks. Anchored so `golang.org/x/net` cannot match a row
	# for some other module that merely mentions it in prose.
	row="$(grep -F -- "| \`${path}\` |" "${doc}" || true)"
	if [ -z "${row}" ]; then
		fail "${path} — no row in the inventory table (pinned ${version})" \
			"${path} is a direct dependency with no row in the dependency inventory table. Add one, or drop the dependency."
		continue
	fi

	claimed="$(printf '%s' "${row}" | grep -oE 'Pinned at v[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | awk '{print $3}' || true)"
	if [ -z "${claimed}" ]; then
		fail "${path} — row has no 'Pinned at vX.Y.Z' (go.mod: ${version})" \
			"The ${path} row does not state a pinned version. Add 'Pinned at ${version}.'"
	elif [ "${claimed}" != "${version}" ]; then
		fail "${path} — doc says ${claimed}, go.mod pins ${version}" \
			"The ${path} row says ${claimed} but go.mod pins ${version}."
	else
		note "  ok     ${path} ${version}"
	fi
done <<<"${direct}"

# ---------------------------------------------------------------------------
# 3: the stated count of direct dependencies.
# ---------------------------------------------------------------------------
# Spelled as a word ("ten direct dependencies"), so compare against the word.
number_word() {
	case "$1" in
	1) echo one ;; 2) echo two ;; 3) echo three ;; 4) echo four ;;
	5) echo five ;; 6) echo six ;; 7) echo seven ;; 8) echo eight ;;
	9) echo nine ;; 10) echo ten ;; 11) echo eleven ;; 12) echo twelve ;;
	*) echo "$1" ;;
	esac
}
want_word="$(number_word "${count}")"
claimed_count="$(grep -oE '\*\*[a-z]+ direct dependencies\*\*' "${doc}" | head -n1 | sed -E 's/\*\*([a-z]+) direct dependencies\*\*/\1/' || true)"
if [ -z "${claimed_count}" ]; then
	fail "dependency count — no '**N direct dependencies**' sentence found" \
		"Could not find the '**N direct dependencies**' sentence to check against go.mod."
elif [ "${claimed_count}" != "${want_word}" ]; then
	fail "dependency count — doc says ${claimed_count}, go.mod declares ${count} (${want_word})" \
		"The document says '${claimed_count} direct dependencies' but go.mod declares ${count}."
else
	note "  ok     dependency count: ${want_word} (${count})"
fi

# ---------------------------------------------------------------------------
# 4: the build-step "(currently vX)" notes.
# ---------------------------------------------------------------------------
# Each build-step section states the version its install path resolves from
# go.mod. Matched within the section rather than globally, so the two sections
# cannot satisfy each other's check.
check_build_step_note() {
	section="$1" # heading text, e.g. "The pdf_oxide build step"
	path="$2"    # module whose version the note should name

	version="$(printf '%s\n' "${direct}" | awk -v p="${path}" '$1 == p {print $2}')"
	[ -n "${version}" ] || return 0 # not a direct dependency here; nothing to check

	# The section body: from its heading to the next heading of the same level.
	body="$(awk -v h="## ${section}" '
		$0 == h      { inside = 1; next }
		inside && /^## / { exit }
		inside       { print }
	' "${doc}")"
	if [ -z "${body}" ]; then
		fail "${section} — section not found" \
			"Could not find the '${section}' section to check its version note."
		return 0
	fi

	# Tolerates the note being wrapped across lines. The backticks below are
	# literal Markdown inside a single-quoted pattern, not substitution.
	# shellcheck disable=SC2016
	claimed="$(printf '%s' "${body}" | tr '\n' ' ' \
		| grep -oE 'derived from `go\.mod` at build time\*\* \(currently[[:space:]]+v[0-9]+\.[0-9]+\.[0-9]+\)' \
		| head -n1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || true)"
	if [ -z "${claimed}" ]; then
		fail "${section} — no '(currently vX.Y.Z)' note found" \
			"The '${section}' section has no '(currently vX.Y.Z)' note to check."
	elif [ "${claimed}" != "${version}" ]; then
		fail "${section} — note says ${claimed}, go.mod pins ${version}" \
			"The '${section}' section says ${claimed} but go.mod pins ${version} for ${path}."
	else
		note "  ok     ${section}: ${version}"
	fi
}

check_build_step_note "The pdf_oxide build step" "github.com/yfedoseev/pdf_oxide/go"
check_build_step_note "The office_oxide build step" "github.com/yfedoseev/office_oxide/go"

# ---------------------------------------------------------------------------
# Report, and optionally repair.
# ---------------------------------------------------------------------------
echo "check-doc-pins: docs/supply-chain.md vs go.mod"
printf '%s' "${report}"

if [ "${drift}" -eq 0 ]; then
	echo "check-doc-pins: OK — ${count} direct dependencies, all documented versions agree"
	exit 0
fi

if [ "${fix}" -eq 0 ]; then
	cat <<-EOF

		check-doc-pins: FAILED — the document disagrees with go.mod.

		go.mod is authoritative. Run:

		    ./check-doc-pins.sh --fix

		to rewrite the stale numbers, then read the diff: a version bump often
		deserves a sentence about what changed, not only a new number.
	EOF
	exit 1
fi

# --fix rewrites only the version tokens this check compares, one row at a
# time, leaving surrounding prose untouched. It cannot add a missing row or
# adjust the count sentence's grammar, so those still fail after a fix.
#
# Each rewriter exits 0 when it changed something and 1 when it did not, so the
# caller can count real edits rather than attempts.
# Single-quoted on purpose: these are Python programs, and nothing in them may
# be expanded by the shell before python3 sees it.
# shellcheck disable=SC2016
fix_row='
import re, sys
doc, path, version = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(doc, encoding="utf-8").read()
marker = "| `" + path + "` |"
out, hit = [], False
for line in s.split("\n"):
    if line.startswith(marker):
        new = re.sub(r"Pinned at v[0-9]+\.[0-9]+\.[0-9]+\.",
                     "Pinned at " + version + ".", line, count=1)
        hit = hit or new != line
        line = new
    out.append(line)
if hit:
    open(doc, "w", encoding="utf-8").write("\n".join(out))
sys.exit(0 if hit else 1)
'

fix_build_step_note='
import re, sys
doc, section, version = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(doc, encoding="utf-8").read()
start = s.find("## " + section)
if start < 0:
    sys.exit(1)
nxt = s.find("\n## ", start + 1)
end = len(s) if nxt < 0 else nxt
body = s[start:end]
new = re.sub(r"(derived from .go\.mod. at build time\*\* \(currently\s+)v[0-9]+\.[0-9]+\.[0-9]+\)",
             lambda m: m.group(1) + version + ")", body, count=1)
if new == body:
    sys.exit(1)
open(doc, "w", encoding="utf-8").write(s[:start] + new + s[end:])
'

fixed=0
while read -r path version; do
	[ -n "${path}" ] || continue
	if python3 -c "${fix_row}" "${doc}" "${path}" "${version}"; then
		fixed=$((fixed + 1))
	fi
done <<<"${direct}"

# The build-step notes, matched in their own sections.
for pair in "The pdf_oxide build step:github.com/yfedoseev/pdf_oxide/go" \
	"The office_oxide build step:github.com/yfedoseev/office_oxide/go"; do
	section="${pair%%:*}"
	path="${pair#*:}"
	version="$(printf '%s\n' "${direct}" | awk -v p="${path}" '$1 == p {print $2}')"
	[ -n "${version}" ] || continue
	if python3 -c "${fix_build_step_note}" "${doc}" "${section}" "${version}"; then
		fixed=$((fixed + 1))
	fi
done

echo
echo "check-doc-pins: rewrote ${fixed} version reference(s); re-checking"
echo
exec "${BASH_SOURCE[0]}"
