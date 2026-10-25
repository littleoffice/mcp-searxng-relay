#!/usr/bin/env python3
# check-doc-links.py — check that every relative link in the repository's
# Markdown files points at a file that exists and, when it names a #fragment,
# at a heading that exists in that file.
#
# Usage:
#   ./check-doc-links.py           # check, print each broken link, exit non-zero
#
# Exit codes: 0 all links resolve, 1 broken links found.
#
# WHY THIS EXISTS
#
# The documentation is one short README plus reference pages under docs/, and
# they point at each other by section: docs/configuration.md#oauth-20--oidc,
# docs/security-model.md#ssrf-protection. A section anchor is derived from its
# heading text, so renaming a heading or moving a section to another page
# breaks every link to it — and GitHub renders a broken anchor as a link that
# silently lands at the top of the page. Nothing fails, which is the problem:
# the reader is sent to the wrong place and nobody finds out. This holds the
# links the same way check-doc-pins.sh holds the version numbers.
#
# It is Python rather than shell because resolving GitHub's anchor slugs
# (punctuation stripped, spaces to hyphens, -1/-2 suffixes for duplicate
# headings) is error-prone in sed and awk. Standard library only; runs on the
# python3 every CI runner already has.
#
# WHAT IT CHECKS
#
#   1. Every relative link target exists, resolved from the linking file.
#   2. Every #fragment on a link to a Markdown file (or to the same file)
#      matches a heading in that file, slugged the way GitHub does it.
#
# It deliberately does NOT fetch http(s) links. Their availability is not
# something a commit can break or fix, and a network-dependent check would
# turn CI red for reasons unrelated to the change.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6} (.*)$")


def slug(text):
    """GitHub's heading anchor: lowercase, punctuation dropped, spaces to '-'."""
    t = text.strip().lower()
    t = re.sub(r"[`*]", "", t)
    t = re.sub(r"[^\w\- ]", "", t)
    return t.replace(" ", "-")


def prose_lines(path):
    """The file's lines with fenced code blocks blanked out."""
    out, fence = [], False
    for line in path.read_text(encoding="utf-8").split("\n"):
        if line.startswith("```"):
            fence = not fence
            out.append("")
            continue
        out.append("" if fence else line)
    return out


def anchors(path):
    seen, out = {}, set()
    for line in prose_lines(path):
        m = HEADING.match(line)
        if m:
            s = slug(m.group(1))
            n = seen.get(s, 0)
            out.add(s if n == 0 else f"{s}-{n}")
            seen[s] = n + 1
    return out


def main():
    files = sorted(p for p in ROOT.rglob("*.md") if ".git" not in p.parts)
    cache, broken = {}, 0
    for md in files:
        # Join the lines so link text soft-wrapped across lines still matches.
        text = " ".join(prose_lines(md))
        for m in LINK.finditer(text):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path, _, frag = target.partition("#")
            dest = md if path == "" else (md.parent / path).resolve()
            where = md.relative_to(ROOT)
            if not dest.exists():
                print(f"{where}: {target}: no such file")
                broken += 1
                continue
            if frag and dest.suffix == ".md":
                if dest not in cache:
                    cache[dest] = anchors(dest)
                if frag not in cache[dest]:
                    print(f"{where}: {target}: no heading with that anchor")
                    broken += 1
    print(f"check-doc-links: {len(files)} Markdown files, {broken} broken link(s)")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
