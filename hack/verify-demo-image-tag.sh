#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# The demo image's tag is the only thing that makes `helm upgrade --install`
# roll the proxy pods after a rebuild: nothing else in the pod template moves.
# A tag derived from `git describe` alone is constant across two rebuilds of a
# dirty tree at one HEAD, so the second rebuild is side-loaded, Helm sees an
# unchanged template, the old containers keep serving the previous build, and
# check.sh - comparing against that same constant tag - accepts it.
#
# Two guards: the derivation must be the one place the tag comes from, and two
# consecutive dirty builds must produce different tags while a clean tree keeps
# a human-readable one.
rc=0
root=$(cd "$(dirname "$0")/.." && pwd)
fail() { echo "$*" >&2; rc=1; }

# Guard 1: nothing re-derives the tag. up.sh writes it to .state and check.sh
# reads it back, so a standalone check.sh compares against the value that was
# actually deployed rather than against whatever the tree describes as now.
# shellcheck disable=SC2016  # `git describe` is the literal being sought.
hits=$(grep -n 'git describe' "$root"/hack/metrics-demo/*.sh \
  | grep -v '^[^:]*imagetag\.sh:' \
  | grep -v '^[^:]*:[0-9]*:[[:space:]]*#' || true)
if [ -n "$hits" ]; then
  fail "the demo image tag is derived outside hack/metrics-demo/imagetag.sh, so up.sh and check.sh can disagree about what was deployed:"
  printf '%s\n' "$hits" | sed 's/^/  /' >&2
fi

# Guard 2: the derivation itself, against a throwaway repository so the tree
# can be made clean and then dirty without touching this one.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
repo=$tmp/repo
mkdir -p "$repo"
(
  cd "$repo"
  git init -q .
  git config user.email demo@example.com
  git config user.name demo
  git config commit.gpgsign false
  echo one >tracked.txt
  git add tracked.txt
  git commit -qm "init"
  git tag v0.1.0
)

cd "$repo"
export KUBE_ROOT=$repo
# shellcheck source=hack/metrics-demo/imagetag.sh
. "$root/hack/metrics-demo/imagetag.sh"

printf 'binary-one' >"$tmp/artifact"
demo_build_identity CLEAN_TAG CLEAN_VER "$tmp/artifact"
[ "$CLEAN_TAG" = "demo-v0.1.0" ] || fail "a clean tree must keep a human-readable tag, got '$CLEAN_TAG', want 'demo-v0.1.0'"
[ "$CLEAN_VER" = "v0.1.0" ] || fail "a clean tree must report version 'v0.1.0', got '$CLEAN_VER'"

# Two consecutive rebuilds of a dirty tree at one HEAD. The artifact changes
# between them exactly as a real rebuild's does - the version stamp carries the
# build date - and each must get its own tag, or the second rebuild is invisible
# to Helm.
echo two >>"$repo/tracked.txt"
printf 'binary-two' >"$tmp/artifact"
demo_build_identity DIRTY_TAG_1 DIRTY_VER_1 "$tmp/artifact"
printf 'binary-three' >"$tmp/artifact"
demo_build_identity DIRTY_TAG_2 DIRTY_VER_2 "$tmp/artifact"

[ "$DIRTY_VER_1" = "v0.1.0-dirty" ] || fail "a dirty tree must report version 'v0.1.0-dirty', got '$DIRTY_VER_1'"
[ "$DIRTY_TAG_1" != "$CLEAN_TAG" ] || fail "a dirty rebuild reused the clean tree's tag '$CLEAN_TAG'; helm upgrade would see no change"
[ "$DIRTY_TAG_1" != "$DIRTY_TAG_2" ] || fail "two consecutive dirty rebuilds at one HEAD both produced '$DIRTY_TAG_1'; the second would be side-loaded under a tag the pods already run, so the previous build keeps serving"
case "$DIRTY_TAG_1" in
  demo-v0.1.0-dirty-*) ;;
  *) fail "a dirty tag must stay recognisable as v0.1.0-dirty, got '$DIRTY_TAG_1'" ;;
esac

# An untracked file dirties the build without changing `git describe --dirty`,
# so it must change the tag too: the binary it produces is not the committed one.
(cd "$repo" && git checkout -q -- tracked.txt)
printf 'binary-four' >"$tmp/artifact"
touch "$repo/untracked.go"
demo_build_identity UNTRACKED_TAG UNTRACKED_VER "$tmp/artifact"
[ "$UNTRACKED_TAG" != "$CLEAN_TAG" ] || fail "an untracked file left the tag at '$CLEAN_TAG', so a dirty build would be deployed under a clean tree's tag"
[ "$UNTRACKED_VER" = "v0.1.0-dirty" ] || fail "an untracked file must still report a dirty version, got '$UNTRACKED_VER'"

[ $rc -eq 0 ] && echo "metrics-demo image tag: ok"
exit $rc
