#!/bin/sh
# Copyright Jetstack Ltd. See LICENSE for details.

set -eu

fail() { printf '%s\n' "release-contract-check: $*" >&2; exit 1; }
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

for file in .github/workflows/pr-release-metadata.yml .github/workflows/prepare-release.yml .github/workflows/release.yaml docs/releases.md; do
	[ -f "$file" ] || fail "missing $file"
done
grep -q '^  workflow_dispatch:' .github/workflows/prepare-release.yml || fail "Prepare Release must be manually dispatched"
grep -q 'group: prepare-release' .github/workflows/prepare-release.yml || fail "Prepare Release must be serialized"
grep -q 'release/next' .github/workflows/prepare-release.yml || fail "Prepare Release must own release/next"
grep -q 'autorelease: pending' .github/workflows/prepare-release.yml || fail "release PR must carry autorelease: pending"
grep -q "head.ref == 'release/next'" .github/workflows/release.yaml || fail "Release must only accept release/next"
grep -q "contains(github.event.pull_request.labels.*.name, 'autorelease: pending')" .github/workflows/release.yaml || fail "Release must require the automation label"
grep -q '^  group: release' .github/workflows/release.yaml || fail "Release must be serialized"
grep -q 'uses: ./.github/workflows/e2e.yaml' .github/workflows/release.yaml || fail "Release must run reusable E2E"
grep -q 'target_ref: \${{ needs.verify.outputs.sha }}' .github/workflows/release.yaml || fail "Release E2E must test the resolved release commit"
grep -q 'git tag -a' .github/workflows/release.yaml || fail "Release must create an annotated tag after verification"
grep -q 'exactly one' .github/workflows/pr-release-metadata.yml || fail "PR metadata must enforce exactly one release label"
grep -q '.changes/unreleased' .github/workflows/pr-release-metadata.yml || fail "PR metadata must enforce changelog fragments"
grep -q 'Ordinary pull requests never publish' docs/releases.md || fail "release docs must describe the publication gate"
grep -q 'Prepare Release' README.md || fail "README must describe the explicit prepare step"
printf '%s\n' 'release-contract-check: ok'
