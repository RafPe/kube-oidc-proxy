#!/usr/bin/env bash
# Usage: git-guard-test.sh <git command>
#
# Test the git wrapper that claude-review.yaml installs on PATH. Run it in a
# git checkout. One commit is enough.
# The script stops with exit status 1 at the first wrong result.
set -euo pipefail

git_cmd="$1"
out_dir="$(mktemp -d)"
trap 'rm -rf "${out_dir}"' EXIT

expect() { # <refused|passed> <git arguments...>
  local want="$1" got rc=0
  shift
  "${git_cmd}" "$@" >/dev/null 2>&1 || rc=$?
  case "${rc}" in
    0) got=passed ;;
    2) got=refused ;;
    *) got="git error" ;;
  esac
  if [ "${got}" != "${want}" ]; then
    echo "git-guard-test: want ${want}, got ${got} (exit ${rc}): git $*" >&2
    exit 1
  fi
}

expect refused diff --output="${out_dir}/a" HEAD
expect refused show --output "${out_dir}/b" HEAD
expect refused log --ou="${out_dir}/c" -1
expect refused log --outp "${out_dir}/d" -1
expect refused -c core.pager=cat diff --output="${out_dir}/e" HEAD
expect refused -C . show --output="${out_dir}/f" HEAD
expect passed log --oneline -1
expect passed diff --stat HEAD
expect passed diff --name-only HEAD
expect passed show --stat HEAD
expect passed diff --output-indicator-new=+ HEAD
expect passed -c core.pager=cat log -1 --oneline
expect passed rev-parse --git-dir

if [ -n "$(ls -A "${out_dir}")" ]; then
  echo "git-guard-test: a refused command wrote a file" >&2
  exit 1
fi
echo "git-guard-test: all cases passed"
