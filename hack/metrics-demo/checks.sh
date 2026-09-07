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
