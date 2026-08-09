#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
#
# The e2e suite is sharded across a GitHub Actions matrix by Ginkgo label (see
# .github/workflows/e2e.yaml). A case container that carries no shard label
# runs in *zero* shards and silently stops gating PRs, so this check asserts
# that every framework.CasesDescribe() container declares exactly one label
# from the known shard set.
#
# Keep SHARDS in lockstep with the matrix values in .github/workflows/e2e.yaml.
set -euo pipefail

CASES_DIR="${1:-test/e2e/suite/cases}"
SHARDS=(shard-a shard-b shard-c)

shard_pattern="$(IFS='|'; echo "${SHARDS[*]}")"
rc=0
total=0

while IFS= read -r file; do
  containers="$(grep -c 'framework\.CasesDescribe(' "$file" || true)"
  [ "$containers" -gt 0 ] || continue
  total=$((total + containers))

  # Every shard label, valid or not, so typos are reported rather than ignored.
  labels="$(grep -oE 'Label\("shard-[A-Za-z0-9_-]*"\)' "$file" || true)"
  valid="$(printf '%s\n' "$labels" | grep -cE "Label\(\"($shard_pattern)\"\)" || true)"
  invalid="$(printf '%s\n' "$labels" | grep -vE "Label\(\"($shard_pattern)\"\)" | grep -c . || true)"

  if [ "$invalid" -ne 0 ]; then
    echo "$file: unknown shard label(s): $(printf '%s\n' "$labels" | grep -vE "Label\(\"($shard_pattern)\"\)" | tr '\n' ' ')" >&2
    echo "  known shards: ${SHARDS[*]}" >&2
    rc=1
  fi

  if [ "$valid" -ne "$containers" ]; then
    echo "$file: $containers CasesDescribe container(s) but $valid shard label(s); each container needs exactly one Label(\"shard-*\")" >&2
    rc=1
  fi
done < <(find "$CASES_DIR" -type f -name '*.go' | sort)

if [ "$total" -eq 0 ]; then
  echo "no framework.CasesDescribe() containers found under $CASES_DIR; is the path right?" >&2
  exit 1
fi

if [ "$rc" -eq 0 ]; then
  echo "verify-e2e-shards: $total e2e case container(s) each carry exactly one of: ${SHARDS[*]}"
fi

exit "$rc"
