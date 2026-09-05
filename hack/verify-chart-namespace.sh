#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# `helm install` places namespaced objects in the release namespace itself, but
# `helm template | kubectl apply` does not: an object without metadata.namespace
# lands in the caller's current namespace while the ClusterRoleBinding still
# names the rendered one, so the proxy runs without its RBAC grants. Every
# namespaced object must therefore carry the release namespace explicitly, and
# cluster-scoped objects must not carry one at all.
CHART=chart/kube-oidc-proxy
NS=verify-ns
check() {
  local label=$1; shift
  local rows
  rows=$(helm template kop "$CHART" --namespace "$NS" "$@" \
    | yq -r 'select(.kind != null) | [.kind, .metadata.name, .metadata.namespace // "-"] | @tsv')
  [ -n "$rows" ] || { echo "$label: nothing rendered" >&2; exit 1; }
  while IFS=$'\t' read -r kind name ns; do
    case "$kind" in
      ClusterRole|ClusterRoleBinding)
        [ "$ns" = "-" ] || { echo "$label: cluster-scoped $kind/$name carries namespace $ns" >&2; exit 1; } ;;
      *)
        [ "$ns" = "$NS" ] || { echo "$label: $kind/$name rendered with namespace '$ns', expected $NS" >&2; exit 1; } ;;
    esac
  done <<<"$rows"
  echo "$label: $(wc -l <<<"$rows" | tr -d ' ') objects in $NS"
}

check "single-issuer" -f "$CHART/ci/single-issuer-values.yaml"
check "multi-issuer" -f "$CHART/ci/multi-issuer-values.yaml"
check "ingress" -f "$CHART/ci/single-issuer-values.yaml" --set ingress.enabled=true \
  --set 'ingress.hosts[0].host=proxy.example.com' --set 'ingress.hosts[0].paths[0].path=/' \
  --set 'ingress.hosts[0].paths[0].pathType=Prefix'
check "cert-manager" -f "$CHART/ci/single-issuer-values.yaml" \
  --set tls.certManager=true --set tls.selfSigned=true
check "pdb" -f "$CHART/ci/single-issuer-values.yaml" --set podDisruptionBudget.enabled=true

echo "chart namespaces: ok"
