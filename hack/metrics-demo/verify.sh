#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# Every path below - the chart, the values files, the state directory - is
# relative to the repository root, so anchor there instead of trusting the
# caller's working directory. Run from anywhere else the first thing to fail
# was the state check, reporting "missing hack/metrics-demo/.state/..." about
# a demo that was in fact up. The sourced helpers below are named relatively
# too, so this has to come first.
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Every dashboard panel must return data against the demo cluster, and the
# screenshots must be rendered from those dashboards with that data. A panel
# without data is a dashboard that lies; this fails before a screenshot can.
STATE=hack/metrics-demo/.state
KUBECONFIG=$STATE/kubeconfig; export KUBECONFIG
CHART=chart/kube-oidc-proxy
mkdir -p docs/dashboards

# Both forwards bind a port kubectl picks. With a fixed port, a forward left
# behind by another cluster answers instead and this script happily proves the
# panels of a Prometheus that has never seen the demo; the announced port is
# also the signal that the listener is bound, so nothing has to sleep and
# hope.
# shellcheck source=hack/metrics-demo/checks.sh
. hack/metrics-demo/checks.sh
# shellcheck source=hack/metrics-demo/portforward.sh
. hack/metrics-demo/portforward.sh
trap pf_cleanup EXIT
pf_start PROM monitoring svc/kps-kube-prometheus-stack-prometheus 9090
pf_start GRAFANA monitoring svc/kps-grafana 80

promq() {
  pf_check || return 1
  curl -sfG "http://127.0.0.1:$PROM/api/v1/query" --data-urlencode "query=$1"
}

# The same query over the window the screenshots are rendered from, at the
# step Grafana would use. A panel that draws a line is proved by points in the
# window, not by whatever the expression happens to evaluate to at this one
# instant.
promqr() {
  pf_check || return 1
  curl -sfG "http://127.0.0.1:$PROM/api/v1/query_range" \
    --data-urlencode "query=$1" \
    --data-urlencode "start=$RENDER_FROM" \
    --data-urlencode "end=$RENDER_TO" \
    --data-urlencode "step=60"
}

# The Prometheus on the other end is this demo's, not a leftover: it scrapes
# targets in the demo namespace. Asserted before the panels, so "no data for"
# can only mean the panel, never the wrong Prometheus.
targets=$(promq 'up{namespace="proxy"}' | jq '.data.result | length')
if [ "${targets:-0}" -eq 0 ]; then
  echo "the Prometheus on 127.0.0.1:$PROM has no targets in namespace proxy; it is not this demo's" >&2
  exit 1
fi

# Substitute the template variables the way Grafana would for the demo.
expand() { sed -e 's/\$namespace/proxy/g' -e 's/\$pod/.+/g' -e 's/\$__rate_interval/2m/g' -e 's/\${datasource}//g'; }

# The window the screenshots below are rendered from (from=now-30m), so the
# proof and the picture are the same data.
RENDER_TO=$(date +%s)
RENDER_FROM=$((RENDER_TO - 1800))

# A result is not the same thing as a value. Prometheus answers "NaN" for
# histogram_quantile over a bucket set with no observations and for every
# ratio with a zero denominator, and "+Inf"/"-Inf" for a division by zero with
# a non-zero numerator; each of those is one result, which the old count-only
# test accepted, and each draws nothing at all. So: a stat that reads the
# state now must have a finite value now, and a panel that draws a line over
# the window must have at least one finite point in it.
#
# The instant flag and the expression are joined by a unit separator rather
# than by @tsv, because @tsv escapes the backslashes in a label_replace
# pattern and would hand Prometheus a different query than the dashboard has.
SEP=$(printf '\037')
rc=0
for f in "$CHART"/dashboards/*.json; do
  name=$(basename "$f" .json)
  while IFS= read -r line; do
    instant=${line%%"$SEP"*}
    expr=${line#*"$SEP"}
    q=$(printf '%s' "$expr" | expand)
    if [ "$instant" = true ]; then
      body=$(promq "$q") || exit 1
    else
      body=$(promqr "$q") || exit 1
    fi
    n=$(printf '%s' "$body" | jq '.data.result | length')
    if [ "${n:-0}" -eq 0 ]; then echo "$name: no data for: $expr" >&2; rc=1; continue; fi
    if [ "$instant" = true ]; then
      bad=$(printf '%s' "$body" | demo_nonfinite | sort -u | tr '\n' ' ')
      if [ -n "$bad" ]; then
        echo "$name: not a finite value (${bad% }) for: $expr" >&2; rc=1
      fi
    else
      finite=$(printf '%s' "$body" | demo_finite | grep -c . || true)
      if [ "${finite:-0}" -eq 0 ]; then
        echo "$name: no finite point in the render window for: $expr" >&2; rc=1
      fi
    fi
  done < <(jq -r --arg sep "$SEP" '.. | objects | select(has("expr"))
             | ((.instant // false) | tostring) + $sep + .expr' "$f")
done
[ $rc -eq 0 ] || exit 1

# Screenshots through Grafana's image renderer (grafana.imageRenderer.enabled
# in the demo values), anonymous viewer access, kiosk mode, the last 30 min.
for f in "$CHART"/dashboards/*.json; do
  name=$(basename "$f" .json)
  uid=$(jq -r .uid "$f")
  pf_check || exit 1
  curl -sf "http://127.0.0.1:$GRAFANA/render/d/$uid/$name?orgId=1&kiosk&from=now-30m&to=now&width=1920&height=1800&tz=UTC" -o "docs/dashboards/$name.png"
  # A rendered dashboard with data is not a tiny image.
  [ "$(demo_file_size "docs/dashboards/$name.png")" -gt 150000 ] \
    || { echo "docs/dashboards/$name.png is suspiciously small" >&2; exit 1; }
done
echo "metrics demo: every panel has data; screenshots in docs/dashboards/"
