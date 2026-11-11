#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# extraEnv lands in the proxy container next to the OIDC_* variables the chart
# generates, in both the single- and the multi-issuer layout, and a name the
# chart already sets fails the render instead of silently shadowing it.
CHART=chart/kube-oidc-proxy
render() {
  helm template kop "$CHART" --show-only templates/deployment.yaml "$@"
}
out=$(render -f "$CHART/ci/single-issuer-values.yaml")
! grep -q 'HTTPS_PROXY' <<<"$out" || { echo "extraEnv rendered without being set" >&2; exit 1; }
for values in single-issuer multi-issuer; do
  out=$(render -f "$CHART/ci/$values-values.yaml" \
    --set 'extraEnv[0].name=HTTPS_PROXY' --set 'extraEnv[0].value=http://proxy.example.com:3128' \
    --set 'extraEnv[1].name=NO_PROXY' --set 'extraEnv[1].value=.svc')
  grep -q -- '- name: HTTPS_PROXY' <<<"$out" || { echo "$values: extraEnv HTTPS_PROXY not rendered" >&2; exit 1; }
  grep -q -- 'value: http://proxy.example.com:3128' <<<"$out" || { echo "$values: extraEnv value not rendered" >&2; exit 1; }
  grep -q -- '- name: NO_PROXY' <<<"$out" || { echo "$values: extraEnv NO_PROXY not rendered" >&2; exit 1; }
done
out=$(render -f "$CHART/ci/single-issuer-values.yaml" --set 'extraEnv[0].name=HTTPS_PROXY' --set 'extraEnv[0].value=x')
grep -q -- '- name: OIDC_ISSUER_URL' <<<"$out" || { echo "extraEnv replaced the generated OIDC variables" >&2; exit 1; }
if render -f "$CHART/ci/single-issuer-values.yaml" --set 'extraEnv[0].name=OIDC_ISSUER_URL' \
  --set 'extraEnv[0].value=https://other' >/dev/null 2>&1; then
  echo "extraEnv overriding a chart-generated OIDC variable did not fail" >&2; exit 1
fi
echo "chart extraEnv: ok"
