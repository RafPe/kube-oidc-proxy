#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
STATE=hack/metrics-demo/.state
KUBECONFIG=$STATE/kubeconfig; export KUBECONFIG
PROXY_PODS=(app.kubernetes.io/name=kube-oidc-proxy app.kubernetes.io/instance=kop)
for f in kubeconfig issuer-ca.pem issuer-key.pem issuer-url proxy-ca.pem image-tag image-version; do
  [ -s "$STATE/$f" ] || { echo "missing $STATE/$f" >&2; exit 1; }
done
# What up.sh built and side-loaded, read back rather than re-derived: the tree
# can have moved on since - a commit, an edit, a `git checkout` - and the
# question here is what the pods are running, not what the tree describes now.
IMAGE_TAG=$(cat "$STATE/image-tag")
IMAGE_VERSION=$(cat "$STATE/image-version")
PROXY_IMAGE=kube-oidc-proxy:$IMAGE_TAG
kubectl -n monitoring rollout status deploy/kps-grafana --timeout=1s >/dev/null || { echo "grafana not ready" >&2; exit 1; }
kubectl -n monitoring get prometheus -o name | grep -q . || { echo "no Prometheus" >&2; exit 1; }
kubectl -n proxy rollout status deploy/kop-kube-oidc-proxy --timeout=1s >/dev/null || { echo "proxy not ready" >&2; exit 1; }
kubectl -n proxy get servicemonitor kop-kube-oidc-proxy -o name >/dev/null || { echo "no ServiceMonitor" >&2; exit 1; }
# Every proxy pod runs the image this tree builds. The selector is the chart's
# own, not "every pod in the namespace": demo-shell and the mock issuer live
# there too and were never meant to run this image. Pods being deleted are
# skipped and the count is polled, because `helm --wait` and `rollout status`
# both return as soon as the new pods are ready, while the pod they replaced
# is still Terminating - listing once races the rollout and reads the outgoing
# build.
sel=$(IFS=,; echo "${PROXY_PODS[*]}")
want=$(kubectl -n proxy get deploy kop-kube-oidc-proxy -o jsonpath='{.spec.replicas}')
n=0; fresh=0; pods=""
for _ in $(seq 1 20); do
  pods=$(kubectl -n proxy get pods -l "$sel" -o json \
    | jq -r '.items[] | select(.metadata.deletionTimestamp == null)
             | .metadata.name + " " + (.spec.containers | map(.image) | join(","))')
  n=$(printf '%s\n' "$pods" | grep -c . || true)
  fresh=$(printf '%s\n' "$pods" | grep -cF " $PROXY_IMAGE" || true)
  [ "$n" = "$want" ] && [ "$fresh" = "$want" ] && break
  sleep 3
done
[ "$n" = "$want" ] && [ "$fresh" = "$want" ] || {
  echo "expected $want proxy pods on $PROXY_IMAGE, found $n pod(s), $fresh of them on it:" >&2
  printf '%s\n' "$pods" >&2
  echo "helm upgrade did not roll the pods after the image was rebuilt" >&2
  exit 1
}
echo "proxy pods running $PROXY_IMAGE:"
printf '%s\n' "$pods" | sed 's/^/  /'
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
pf_start PROM monitoring svc/kps-kube-prometheus-stack-prometheus 9090
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

# What each pod reports as its build. The tag assertion above proves the pods
# run the image up.sh side-loaded; this proves that image is the binary up.sh
# built, by comparing the version it stamped with the one every pod exposes.
# The two can only differ if a pod is serving something else, which is exactly
# the failure the tag alone used to hide. Run unconditionally: a dirty version
# is a legitimate thing to be running while developing, and asserting equality
# reports it rather than skipping the check - and because the version comes
# from `git status` and not from `git describe --dirty`, an untracked .go file
# is dirty here too.
while read -r name _; do
  pf_check || exit 1
  pf_start port proxy "pod/$name" 9090 </dev/null
  # shellcheck disable=SC2154  # pf_start assigns `port` with printf -v.
  info=$(curl -sf "http://127.0.0.1:$port/metrics" | grep '^kube_oidc_proxy_build_info' || true)
  [ -n "$info" ] || { echo "pod $name exposed no kube_oidc_proxy_build_info" >&2; exit 1; }
  reported=$(printf '%s' "$info" | sed -n 's/.*[{,]version="\([^"]*\)".*/\1/p')
  [ "$reported" = "$IMAGE_VERSION" ] || {
    echo "pod $name reports build_info version '$reported', but $PROXY_IMAGE was built from '$IMAGE_VERSION'" >&2
    echo "$info" >&2
    exit 1
  }
  echo "  $name $info"
done <<<"$pods"
echo "metrics demo: ready"
