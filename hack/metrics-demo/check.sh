#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
STATE=hack/metrics-demo/.state
KUBECONFIG=$STATE/kubeconfig; export KUBECONFIG
for f in kubeconfig issuer-ca.pem issuer-key.pem issuer-url proxy-ca.pem; do
  [ -s "$STATE/$f" ] || { echo "missing $STATE/$f" >&2; exit 1; }
done
kubectl -n monitoring rollout status deploy/kps-grafana --timeout=1s >/dev/null || { echo "grafana not ready" >&2; exit 1; }
kubectl -n monitoring get prometheus -o name | grep -q . || { echo "no Prometheus" >&2; exit 1; }
kubectl -n proxy rollout status deploy/kop-kube-oidc-proxy --timeout=1s >/dev/null || { echo "proxy not ready" >&2; exit 1; }
kubectl -n proxy get servicemonitor kop-kube-oidc-proxy -o name >/dev/null || { echo "no ServiceMonitor" >&2; exit 1; }
kubectl -n proxy get configmap kop-kube-oidc-proxy-dashboards -o name >/dev/null || { echo "no dashboards ConfigMap" >&2; exit 1; }
# Prometheus has discovered the proxy target and it is up. Discovery is
# asynchronous: the operator regenerates the scrape config from the
# ServiceMonitor and Prometheus reloads it, which took about a minute on the
# reference run, so poll rather than assert once. The query is passed with
# --data-urlencode because =~, {, } and " are not URL-safe and Prometheus
# answers 400 for the raw form. The forward binds a port kubectl picks, not a
# fixed one: a fixed port is answered by whatever already holds it, so a
# forward left behind by another cluster would make this assertion pass
# against a Prometheus that has never seen this demo.
# shellcheck source=hack/metrics-demo/portforward.sh
. hack/metrics-demo/portforward.sh
trap pf_cleanup EXIT
PROM=$(pf_start monitoring svc/kps-kube-prometheus-stack-prometheus 9090)
up=0
for i in $(seq 1 40); do
  pf_check || exit 1
  up=$(curl -sfG "http://127.0.0.1:$PROM/api/v1/query" \
    --data-urlencode 'query=up{job=~".*kube-oidc-proxy.*"}' \
    | jq -r '.data.result[0].value[1] // "0"') || up=0
  [ "$up" = "1" ] && break
  [ $((i % 10)) -eq 0 ] && echo "waiting for Prometheus to discover the proxy target (attempt $i/40)"
  sleep 3
done
[ "$up" = "1" ] || { echo "proxy target not up in Prometheus (up=$up)" >&2; exit 1; }
echo "metrics demo: ready"
