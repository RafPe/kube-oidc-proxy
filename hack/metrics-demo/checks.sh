#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
# shellcheck shell=bash
# Small assertions the demo scripts share, kept here so they can be exercised
# without a cluster. hack/verify-metrics-demo.sh runs them against synthetic
# inputs; check.sh and verify.sh call the same functions against the real one.

# demo_file_size <path> prints the size of a file in bytes as a bare integer.
#
# `wc -c`, not `stat`: the two stat dialects spell the size differently
# (`-f %z` on BSD, `-c %s` on GNU) and trying one then the other does not
# degrade safely, because `-f` means "filesystem status" to GNU coreutils. It
# reads `%z` as a path, prints a multi-line report about the file system to
# *stdout*, and only then exits non-zero - so the `||` fallback appends the
# real size to that report and the caller compares a paragraph of text. `wc`
# is POSIX and needs no dialect detection; it pads its output on BSD, so the
# blanks are stripped and what comes back is always a bare integer.
demo_file_size() {
  local size
  size=$(wc -c <"$1") || return 1
  printf '%s' "${size//[[:space:]]/}"
}

# A Prometheus sample value is a string, and "NaN", "+Inf" and "-Inf" are
# perfectly ordinary members of that set: histogram_quantile over a bucket set
# with no observations answers NaN, and so does every ratio whose denominator
# is zero. A panel drawing NaN draws nothing, so counting results is not proof
# that a panel has data - only counting *finite* results is.
_demo_jq_samples='
  def samples:
    [.data.result[]? | if has("value") then .value else empty end]
    + [.data.result[]? | .values[]?]
    | map(.[1] | tostring);
  def finite:
    test("^-?(?:[0-9]+(?:\\.[0-9]+)?|\\.[0-9]+)(?:[eE][-+]?[0-9]+)?$");
'

# demo_finite reads a Prometheus query or query_range response on stdin and
# prints every finite sample value in it, one per line.
demo_finite() {
  jq -r "$_demo_jq_samples"' samples | map(select(finite)) | .[]'
}

# demo_nonfinite is its complement: every sample value that is not a finite
# decimal, one per line. Empty output means every sample was a number.
demo_nonfinite() {
  jq -r "$_demo_jq_samples"' samples | map(select(finite | not)) | .[]'
}
