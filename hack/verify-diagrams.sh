#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# Hand-authored SVG diagrams must be well-formed XML, carry a <title> for
# screen readers and GitHub's alt rendering, use literal colours (GitHub strips
# CSS variables and currentColor resolves to black on a dark theme), and be
# referenced from at least one document.
[ -d docs/diagrams ] || { echo "docs/diagrams missing" >&2; exit 1; }

# Without nullglob an unmatched glob stays literal and the loop below runs
# once on the pattern itself, which fails as an unreadable file rather than as
# "there are no diagrams". Check the directory first, then let the glob
# expand to nothing and say so.
shopt -s nullglob
svgs=(docs/diagrams/*.svg)
[ "${#svgs[@]}" -gt 0 ] || { echo "docs/diagrams contains no .svg files" >&2; exit 1; }

rc=0
for svg in "${svgs[@]}"; do
  python3 - "$svg" <<'PY' || rc=1
import re, sys, xml.dom.minidom
path = sys.argv[1]
doc = xml.dom.minidom.parse(path)  # raises on malformed XML
root = doc.documentElement
if root.tagName != "svg" or not root.getAttribute("viewBox"):
    print(f"{path}: root must be <svg> with a viewBox"); sys.exit(1)
if not root.getElementsByTagName("title"):
    print(f"{path}: missing <title>"); sys.exit(1)
text = open(path).read()
for bad in ("var(--", "currentColor"):
    if bad in text:
        print(f"{path}: uses {bad}; GitHub does not resolve it"); sys.exit(1)
PY
  name=$(basename "$svg")
  grep -rq "diagrams/$name" docs/*.md || { echo "$svg is not referenced from any doc" >&2; rc=1; }
done
exit $rc
