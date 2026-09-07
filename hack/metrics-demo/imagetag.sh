#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
# shellcheck shell=bash
# The demo proxy image's tag and the version its binary reports, derived in one
# place so up.sh and check.sh can never disagree about what was deployed.
#
# The tag is the only part of the pod template a rebuild moves, so it is what
# makes `helm upgrade --install` roll the proxy pods. `git describe` alone is
# not enough: two rebuilds of a dirty tree at one HEAD describe identically, so
# the second image is side-loaded under a tag the pods already run, Helm sees
# an unchanged template, and the previous build keeps serving while check.sh -
# comparing against that same tag - accepts it.
#
# A dirty tag therefore ends in a digest of the artifact that is actually about
# to ship. It is deliberately not a hash of `git diff HEAD` and the untracked
# file list: hashing the source reintroduces the bug, because two rebuilds of
# an unchanged dirty tree hash the same. The binary does not - `kube::version::
# ldflags` stamps buildDate with the current second - so every dirty rebuild
# gets its own tag and every dirty rebuild rolls the pods. A clean tree needs
# none of this and keeps the human-readable `demo-<version>`.

# _demo_repo_root is where this helper lives, so the version library is found
# whatever the caller's working directory is.
_demo_repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=hack/lib/version.sh
# shellcheck disable=SC1091  # the path is composed, so only `shellcheck -x` follows it.
. "$_demo_repo_root/hack/lib/version.sh"

# demo_version_vars refreshes KUBE_GIT_VERSION and KUBE_GIT_TREE_STATE from the
# tree at KUBE_ROOT. get_version_vars memoises every variable it sets, so a
# second call in the same shell would answer with the first call's tree; unset
# them all first.
demo_version_vars() {
  unset KUBE_GIT_COMMIT KUBE_GIT_TREE_STATE KUBE_GIT_VERSION KUBE_GIT_MAJOR KUBE_GIT_MINOR
  KUBE_ROOT=${KUBE_ROOT:-$_demo_repo_root} kube::version::get_version_vars
}

# demo_artifact_digest echoes a short digest of the file it is given. Portable
# across the macOS build host (shasum) and the Linux CI runner (sha256sum).
demo_artifact_digest() {
  local file=$1 sum
  if [ ! -s "$file" ]; then
    echo "cannot digest the build artifact: $file is missing or empty" >&2
    return 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sum=$(sha256sum "$file")
  elif command -v shasum >/dev/null 2>&1; then
    sum=$(shasum -a 256 "$file")
  else
    echo "neither sha256sum nor shasum is available to digest $file" >&2
    return 1
  fi

  printf '%s' "${sum%% *}" | cut -c1-12
}

# demo_build_identity <tag-outvar> <version-outvar> <built-binary>; assigns the
# image tag and the version that binary stamps into kube_oidc_proxy_build_info.
# Call it after the binary has been built: the version library reads the tree
# the same way the build's own ldflags do, so sampling before `make build`
# risks recording a version the binary does not report.
demo_build_identity() {
  local out_tag=$1 out_ver=$2 artifact=$3
  local version tag digest
  demo_version_vars
  version=${KUBE_GIT_VERSION:-}
  if [ -z "$version" ]; then
    echo "cannot determine the build version: no reachable tag" >&2
    return 1
  fi
  # Docker tags admit no '+', which the version library uses to join the commit.
  tag=demo-$(printf '%s' "$version" | tr '+' '-')
  # Dirty is KUBE_GIT_TREE_STATE, which is `git status`: `git describe --dirty`
  # ignores untracked files, and an untracked .go file changes the binary.
  if [ "${KUBE_GIT_TREE_STATE:-dirty}" != clean ]; then
    digest=$(demo_artifact_digest "$artifact") || return 1
    tag="$tag-$digest"
  fi

  printf -v "$out_tag" '%s' "$tag"
  printf -v "$out_ver" '%s' "$version"
}
