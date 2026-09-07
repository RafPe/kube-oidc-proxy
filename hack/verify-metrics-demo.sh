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

# demo_finite / demo_nonfinite must read a sample value, not count results.
# verify.sh used to accept a panel because the query returned a result; a
# histogram_quantile over an idle bucket set and a ratio over a zero
# denominator both return one result whose value is the string "NaN", which
# Grafana draws as nothing at all.
sample_case() {
  local label=$1 body=$2 want_finite=$3 want_bad=$4 got
  got=$(printf '%s' "$body" | demo_finite | tr '\n' ' ' | sed 's/ $//')
  [ "$got" = "$want_finite" ] || fail "demo_finite($label) = '$got', want '$want_finite'"
  got=$(printf '%s' "$body" | demo_nonfinite | tr '\n' ' ' | sed 's/ $//')
  [ "$got" = "$want_bad" ] || fail "demo_nonfinite($label) = '$got', want '$want_bad'"
}
sample_case "an instant NaN, which used to pass as one result" \
  '{"data":{"resultType":"vector","result":[{"metric":{},"value":[1,"NaN"]}]}}' \
  "" "NaN"
sample_case "an instant +Inf" \
  '{"data":{"resultType":"vector","result":[{"metric":{},"value":[1,"+Inf"]}]}}' \
  "" "+Inf"
sample_case "an ordinary instant value" \
  '{"data":{"resultType":"vector","result":[{"metric":{},"value":[1,"0.125"]}]}}' \
  "0.125" ""
sample_case "a range series that is NaN until traffic starts" \
  '{"data":{"resultType":"matrix","result":[{"metric":{},"values":[[1,"NaN"],[2,"NaN"],[3,"2"]]}]}}' \
  "2" "NaN NaN"
sample_case "a range series that is NaN throughout" \
  '{"data":{"resultType":"matrix","result":[{"metric":{},"values":[[1,"NaN"],[2,"NaN"]]}]}}' \
  "" "NaN NaN"
sample_case "an empty result" '{"data":{"resultType":"vector","result":[]}}' "" ""

# demo_up_pods must answer with the whole set, not with the first element.
# check.sh used to read `.data.result[0].value[1]`, so a Deployment of two
# replicas was declared ready when either one of them was scraped - and when
# the down target happened to sort first it read 0 and the poll timed out for
# no reason anyone could see.
pods_case() {
  local label=$1 body=$2 want=$3 got
  got=$(printf '%s' "$body" | demo_up_pods | tr '\n' ' ' | sed 's/ $//')
  [ "$got" = "$want" ] || fail "demo_up_pods($label) = '$got', want '$want'"
}
pods_case "one pod up, one down" \
  '{"data":{"result":[{"metric":{"pod":"kop-a"},"value":[1,"1"]},{"metric":{"pod":"kop-b"},"value":[1,"0"]}]}}' \
  "kop-a"
pods_case "one pod down, one up (the down one first)" \
  '{"data":{"result":[{"metric":{"pod":"kop-b"},"value":[1,"0"]},{"metric":{"pod":"kop-a"},"value":[1,"1"]}]}}' \
  "kop-a"
pods_case "a single result, up" \
  '{"data":{"result":[{"metric":{"pod":"kop-a"},"value":[1,"1"]}]}}' \
  "kop-a"
pods_case "both up" \
  '{"data":{"result":[{"metric":{"pod":"kop-b"},"value":[1,"1"]},{"metric":{"pod":"kop-a"},"value":[1,"1"]}]}}' \
  "kop-a kop-b"
pods_case "a target with no pod label" \
  '{"data":{"result":[{"metric":{"job":"kop"},"value":[1,"1"]}]}}' \
  ""
pods_case "no targets at all" '{"data":{"result":[]}}' ""

ready_case() {
  local label=$1 body=$2 want=$3 got
  got=$(printf '%s' "$body" | demo_ready_pods | tr '\n' ' ' | sed 's/ $//')
  [ "$got" = "$want" ] || fail "demo_ready_pods($label) = '$got', want '$want'"
}
ready_case "one ready, one still starting" \
  '{"items":[{"metadata":{"name":"kop-a"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},
             {"metadata":{"name":"kop-b"},"status":{"conditions":[{"type":"Ready","status":"False"}]}}]}' \
  "kop-a"
ready_case "a ready pod that is terminating" \
  '{"items":[{"metadata":{"name":"kop-a","deletionTimestamp":"now"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' \
  ""
ready_case "two ready" \
  '{"items":[{"metadata":{"name":"kop-b"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},
             {"metadata":{"name":"kop-a"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' \
  "kop-a kop-b"

[ $rc -eq 0 ] && echo "metrics-demo checks: ok"
exit $rc
