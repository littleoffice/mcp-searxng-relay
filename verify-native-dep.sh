#!/usr/bin/env bash
# verify-native-dep.sh — check a native build artifact against the digest
# pinned in native-deps.sha256.
#
# Usage:
#   ./verify-native-dep.sh <key> <file>
#   ./verify-native-dep.sh --print <library> <version>
#
# The first form is the build-time check. It is used by the Dockerfile and by
# .github/workflows/ci.yml, which is the whole reason it is a script rather
# than a few inlined lines: the same comparison has to happen in both places,
# and two copies of a security check drift.
#
# The second form is the maintenance helper — see native-deps.sha256 for when
# and how to use it.
#
# Exit codes: 0 verified, 1 mismatch or missing pin, 64 usage error.
#
# Every failure path prints the key, the file, both digests where it has them,
# and what to do next. A digest mismatch on a statically linked library is
# either a re-published upstream release or a compromise, and the person
# reading the failure needs enough to tell those apart without re-deriving the
# command that produced it.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="${NATIVE_DEPS_MANIFEST:-${here}/native-deps.sha256}"

die() {
    printf 'verify-native-dep: %s\n' "$1" >&2
    exit "${2:-1}"
}

# assert_no_duplicate_keys rejects a manifest that pins the same key twice.
#
# Run over the whole file rather than just the key being looked up: a duplicate
# anywhere means two lines disagree about what is authoritative, and which one
# wins should never come down to file order. It also has to happen out here
# rather than inside lookup(), because lookup runs in a command substitution —
# a subshell — where `die` would only kill the subshell and the caller would go
# on to report the wrong problem.
assert_no_duplicate_keys() {
    local dupes
    dupes="$(awk -F= '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        { seen[$1]++ }
        END { for (k in seen) if (seen[k] > 1) print k }
    ' "$manifest")"

    if [ -n "$dupes" ]; then
        die "these keys are pinned more than once in $manifest:

$dupes

Two lines disagreeing about one artifact's digest is not a pin. Remove the
duplicates so exactly one entry is authoritative."
    fi
}

# lookup echoes the pinned digest for an exact key, or returns 1.
#
# awk with `$1 == key` is an exact string comparison. That matters: keys carry
# version numbers, so a `grep`/`sed` pattern would treat every '.' as "any
# character" and a prefix match would let a longer key satisfy a shorter one.
# Neither is acceptable in the lookup step of an integrity check.
lookup() {
    local key="$1" hits
    hits="$(awk -F= -v k="$key" '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        $1 == k         { print $2 }
    ' "$manifest")"

    [ -n "$hits" ] || return 1
    printf '%s' "$hits"
}

digest_of() {
    sha256sum "$1" | cut -d' ' -f1
}

# ── --print: regenerate manifest lines for one library/version ───────────────

print_pins() {
    local lib="$1" version="$2" tmp
    tmp="$(mktemp -d)"
    # shellcheck disable=SC2064 # expand tmp now, not at trap time
    trap "rm -rf '$tmp'" EXIT

    case "$lib" in
    office_oxide)
        local arch
        for arch in x86_64 aarch64; do
            curl --proto '=https' --tlsv1.2 -fsSL \
                "https://github.com/yfedoseev/office_oxide/releases/download/${version}/native-linux-${arch}.tar.gz" \
                -o "${tmp}/oo-${arch}.tar.gz"
            printf '%s/%s/native-linux-%s.tar.gz=%s\n' \
                "$lib" "$version" "$arch" "$(digest_of "${tmp}/oo-${arch}.tar.gz")"
        done
        curl --proto '=https' --tlsv1.2 -fsSL \
            "https://raw.githubusercontent.com/yfedoseev/office_oxide/${version}/include/office_oxide_c/office_oxide.h" \
            -o "${tmp}/office_oxide.h"
        printf '%s/%s/office_oxide.h=%s\n' \
            "$lib" "$version" "$(digest_of "${tmp}/office_oxide.h")"
        ;;
    pdf_oxide)
        # Digest the static library as extracted, matching what the build
        # verifies — not the archive, which the build never sees on its own.
        local goarch
        for goarch in amd64 arm64; do
            curl --proto '=https' --tlsv1.2 -fsSL \
                "https://github.com/yfedoseev/pdf_oxide/releases/download/${version}/pdf_oxide-go-ffi-linux-${goarch}.tar.gz" \
                -o "${tmp}/po-${goarch}.tar.gz"
            mkdir -p "${tmp}/x-${goarch}"
            tar -xzf "${tmp}/po-${goarch}.tar.gz" -C "${tmp}/x-${goarch}"
            printf '%s/%s/linux_%s/libpdf_oxide.a=%s\n' \
                "$lib" "$version" "$goarch" \
                "$(digest_of "${tmp}/x-${goarch}/lib/linux_${goarch}/libpdf_oxide.a")"
        done
        ;;
    *)
        die "--print does not know how to fetch '$lib' (known: office_oxide, pdf_oxide)" 64
        ;;
    esac
}

# ── entry point ──────────────────────────────────────────────────────────────

if [ "${1:-}" = "--print" ]; then
    [ $# -eq 3 ] || die "usage: $0 --print <office_oxide|pdf_oxide> <version>" 64
    print_pins "$2" "$3"
    exit 0
fi

[ $# -eq 2 ] || die "usage: $0 <key> <file>   |   $0 --print <library> <version>" 64

key="$1"
file="$2"

[ -r "$manifest" ] || die "digest manifest '$manifest' is not readable"
[ -r "$file" ] || die "artifact '$file' is not readable (download step failed?)"

assert_no_duplicate_keys

if ! expected="$(lookup "$key")"; then
    die "no pinned digest for '$key' in $manifest.

This is what a version bump looks like when the digest pin was not updated
with it. Nothing is verified for this artifact, so the build stops here.

To record the digests for the new version:

    ./verify-native-dep.sh --print <office_oxide|pdf_oxide> <version>

Check the upstream release notes first, then replace that library's block in
native-deps.sha256 with the printed lines."
fi

case "$expected" in
[0-9a-f][0-9a-f]*)
    [ "${#expected}" -eq 64 ] || die "pinned digest for '$key' is ${#expected} characters, want 64"
    ;;
*)
    die "pinned digest for '$key' is not lower-case hex: '$expected'"
    ;;
esac

actual="$(digest_of "$file")"

if [ "$actual" != "$expected" ]; then
    die "DIGEST MISMATCH for '$key'

  file      $file
  expected  $expected
  actual    $actual

The bytes upstream is serving are not the bytes this repository pinned. Either
upstream re-published the release under the same version — in which case
confirm why, then re-pin with './verify-native-dep.sh --print ...' — or the
artifact has been tampered with. Do not bypass this check to get a green
build: this library is statically linked into the relay and runs with its
privileges."
fi

printf 'verify-native-dep: OK %s (sha256 %s…)\n' "$key" "${actual:0:12}"
