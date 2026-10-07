#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# SVG diagrams must be well-formed XML, carry a <title> for screen readers
# and GitHub's alt rendering, and be referenced from at least one document.
# Hand-authored SVGs must use literal colours (CSS variables are not defined
# for them and currentColor resolves to black on a dark theme). Archify
# exports (marked by data-preset on the root) define their own custom
# properties in an embedded stylesheet with a prefers-color-scheme switch, so
# they may use var(--…). No SVG may load an external resource or run a
# script.
[ -d docs/diagrams ] || { echo "docs/diagrams missing" >&2; exit 1; }

# Without nullglob an unmatched glob stays literal and the loop below runs
# once on the pattern itself, which fails as an unreadable file rather than as
# "there are no diagrams". Check the directory first, then let the glob
# expand to nothing and say so.
shopt -s nullglob
svgs=(docs/diagrams/*.svg demo/diagrams/*.svg)
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
# No SVG may load anything: every href/xlink:href and every CSS url() or
# @import must be a fragment (#id) or a data: URL.
def external(ref):
    ref = ref.strip().strip("'\"")
    return ref and not (ref.startswith("#") or ref.startswith("data:"))
def walk(node):
    for child in node.childNodes:
        if child.nodeType != child.ELEMENT_NODE:
            continue
        for attr in ("href", "xlink:href"):
            if child.hasAttribute(attr) and external(child.getAttribute(attr)):
                print(f"{path}: <{child.tagName} {attr}> loads an external resource"); sys.exit(1)
        walk(child)
walk(root)
for m in re.finditer(r"url\(([^)]*)\)|@import\s+([^;]+);", text):
    ref = m.group(1) if m.group(1) is not None else m.group(2)
    if external(ref.replace("url(", "")):
        print(f"{path}: stylesheet loads an external resource: {ref.strip()[:60]}"); sys.exit(1)
if root.getAttribute("data-preset"):
    # Archify export: carries its own custom properties and theme switch.
    if root.getElementsByTagName("script"):
        print(f"{path}: archify export contains a <script>"); sys.exit(1)
    if "prefers-color-scheme" not in text:
        print(f"{path}: archify export lacks the prefers-color-scheme switch; export with the dual-theme 'svg' format"); sys.exit(1)
else:
    for bad in ("var(--", "currentColor"):
        if bad in text:
            print(f"{path}: uses {bad}; GitHub does not resolve it"); sys.exit(1)
PY
  name=$(basename "$svg")
  grep -rq --include='*.md' "diagrams/$name" docs demo || { echo "$svg is not referenced from any document under docs/ or demo/" >&2; rc=1; }
done
exit $rc
