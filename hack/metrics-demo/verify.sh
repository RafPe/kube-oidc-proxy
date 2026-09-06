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

kubectl -n monitoring port-forward svc/kps-kube-prometheus-stack-prometheus 19090:9090 >/dev/null 2>&1 & pf1=$!
kubectl -n monitoring port-forward svc/kps-grafana 13000:80 >/dev/null 2>&1 & pf2=$!
trap 'kill $pf1 $pf2' EXIT; sleep 3

# Substitute the template variables the way Grafana would for the demo.
expand() { sed -e 's/\$namespace/proxy/g' -e 's/\$pod/.+/g' -e 's/\$__rate_interval/2m/g' -e 's/\${datasource}//g'; }

rc=0
for f in "$CHART"/dashboards/*.json; do
  name=$(basename "$f" .json)
  while IFS= read -r expr; do
    q=$(printf '%s' "$expr" | expand)
    n=$(curl -sfG 'http://127.0.0.1:19090/api/v1/query' --data-urlencode "query=$q" | jq '.data.result | length')
    if [ "${n:-0}" -eq 0 ]; then echo "$name: no data for: $expr" >&2; rc=1; fi
  done < <(jq -r '.. | objects | select(has("expr")) | .expr' "$f")
done
[ $rc -eq 0 ] || exit 1

# Screenshots through Grafana's image renderer (grafana.imageRenderer.enabled
# in the demo values), anonymous viewer access, kiosk mode, the last 30 min.
for f in "$CHART"/dashboards/*.json; do
  name=$(basename "$f" .json)
  uid=$(jq -r .uid "$f")
  curl -sf "http://127.0.0.1:13000/render/d/$uid/$name?orgId=1&kiosk&from=now-30m&to=now&width=1920&height=1800&tz=UTC" -o "docs/dashboards/$name.png"
  # A rendered dashboard with data is not a tiny image.
  [ "$(stat -f %z "docs/dashboards/$name.png" 2>/dev/null || stat -c %s "docs/dashboards/$name.png")" -gt 150000 ] \
    || { echo "docs/dashboards/$name.png is suspiciously small" >&2; exit 1; }
done
echo "metrics demo: every panel has data; screenshots in docs/dashboards/"
