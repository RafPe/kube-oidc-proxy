#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# helm lint and helm template accept any valid YAML. A value in the wrong shape
# can render a field the Kubernetes schema does not know, and a lenient apply
# drops it without an error. kubeconform -strict rejects unknown fields, so
# every fixture render must pass it, and a wrong shape must fail the render.
CHART=chart/kube-oidc-proxy
KUBECONFORM_VERSION="v0.8.0"
kubeconform() {
  go run "github.com/yannh/kubeconform/cmd/kubeconform@${KUBECONFORM_VERSION}" "$@"
}
validate() {
  # ServiceMonitor and PodMonitor are CRDs without a schema in the default
  # catalogue; the built-in kinds are still checked strictly.
  kubeconform -strict -summary -ignore-missing-schemas -
}
for values in "$CHART"/ci/*-values.yaml; do
  helm template kop "$CHART" -f "$values" | validate \
    || { echo "$values: rendered manifests fail the Kubernetes schema" >&2; exit 1; }
done
# extraEnv written as a map, not a list: the chart must refuse it, not render
# the entry as an unknown container field.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf 'extraEnv:\n  HTTPS_PROXY:\n    name: HTTPS_PROXY\n    value: http://proxy.example.com:3128\n' >"$tmp"
if out=$(helm template kop "$CHART" -f "$CHART/ci/single-issuer-values.yaml" -f "$tmp" 2>/dev/null); then
  validate <<<"$out" >&2 || true
  echo "extraEnv as a map rendered instead of failing the render" >&2
  exit 1
fi
echo "chart schema: ok"
