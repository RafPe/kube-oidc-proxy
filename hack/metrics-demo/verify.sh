#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
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
# shellcheck source=hack/metrics-demo/portforward.sh
. hack/metrics-demo/portforward.sh
trap pf_cleanup EXIT
PROM=$(pf_start monitoring svc/kps-kube-prometheus-stack-prometheus 9090)
GRAFANA=$(pf_start monitoring svc/kps-grafana 80)

promq() {
  pf_check || return 1
  curl -sfG "http://127.0.0.1:$PROM/api/v1/query" --data-urlencode "query=$1"
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

rc=0
for f in "$CHART"/dashboards/*.json; do
  name=$(basename "$f" .json)
  while IFS= read -r expr; do
    q=$(printf '%s' "$expr" | expand)
    n=$(promq "$q" | jq '.data.result | length') || exit 1
    if [ "${n:-0}" -eq 0 ]; then echo "$name: no data for: $expr" >&2; rc=1; fi
  done < <(jq -r '.. | objects | select(has("expr")) | .expr' "$f")
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
  [ "$(stat -f %z "docs/dashboards/$name.png" 2>/dev/null || stat -c %s "docs/dashboards/$name.png")" -gt 150000 ] \
    || { echo "docs/dashboards/$name.png is suspiciously small" >&2; exit 1; }
done
echo "metrics demo: every panel has data; screenshots in docs/dashboards/"
