#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# Unit cases for the assertions hack/metrics-demo/checks.sh makes, run without
# a cluster. Each one is a failure the demo scripts made silently before it.
rc=0
fail() { echo "$*" >&2; rc=1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# shellcheck source=hack/metrics-demo/checks.sh
. hack/metrics-demo/checks.sh

# demo_file_size must answer with a bare integer whatever `stat` is on PATH.
# `stat -f` means "filesystem status" to GNU coreutils, which reads the format
# string as a path, prints a multi-line report about the file system to stdout
# and only then fails - so `stat -f %z f || stat -c %s f` hands that report to
# `[ ... -gt N ]`, which dies with "integer expression expected". The size is
# read with `wc -c` instead, which is POSIX and needs no dialect detection.
printf '0123456789' >"$tmp/ten"
size_case() {
  local label=$1 shim=$2 got
  local bin="$tmp/bin-$label"
  mkdir -p "$bin"
  ln -sf "$shim" "$bin/stat"
  got=$(PATH="$bin:$PATH" demo_file_size "$tmp/ten")
  case "$got" in
    10) ;;
    *) fail "demo_file_size with $label stat on PATH ($shim) printed '$got', want the bare integer 10" ;;
  esac
}
for candidate in /opt/homebrew/bin/gstat /usr/bin/gstat /usr/local/bin/gstat; do
  [ -x "$candidate" ] || continue
  size_case gnu "$candidate"
  break
done
for candidate in /usr/bin/stat /bin/stat; do
  [ -x "$candidate" ] || continue
  # Only the BSD one: a Linux /usr/bin/stat is GNU and is covered above.
  if "$candidate" -f %z "$tmp/ten" >/dev/null 2>&1; then
    size_case bsd "$candidate"
  else
    size_case gnu "$candidate"
  fi
  break
done

[ $rc -eq 0 ] && echo "metrics-demo checks: ok"
exit $rc
