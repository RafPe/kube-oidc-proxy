#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# extraEnv lands in the proxy container after the OIDC_* variables the chart
# generates, in both the single- and the multi-issuer layout, and an OIDC_*
# name fails the render instead of silently shadowing a generated variable.
CHART=chart/kube-oidc-proxy
render() {
  helm template kop "$CHART" --show-only templates/deployment.yaml "$@"
}
env_names() {
  yq '.spec.template.spec.containers[0].env[].name' | paste -sd' ' -
}
fail() { echo "$*" >&2; exit 1; }

# The env names each fixture renders without extraEnv.
declare -A base
for values in single-issuer multi-issuer; do
  base[$values]=$(render -f "$CHART/ci/$values-values.yaml" | env_names)
  grep -qw HTTPS_PROXY <<<"${base[$values]}" && fail "$values: extraEnv rendered without being set"
done
grep -qw OIDC_ISSUER_URL <<<"${base[single-issuer]}" \
  || fail "single-issuer: generated OIDC variables missing: ${base[single-issuer]}"

# extraEnv entries come after the generated ones, in order, with their values.
for values in single-issuer multi-issuer; do
  out=$(render -f "$CHART/ci/$values-values.yaml" \
    --set 'extraEnv[0].name=HTTPS_PROXY' --set 'extraEnv[0].value=http://proxy.example.com:3128' \
    --set 'extraEnv[1].name=NO_PROXY' --set 'extraEnv[1].value=.svc')
  want=$(echo "${base[$values]} HTTPS_PROXY NO_PROXY" | xargs)
  got=$(env_names <<<"$out")
  [[ "$got" == "$want" ]] || fail "$values: env names are '$got', want '$want'"
  v=$(yq '.spec.template.spec.containers[0].env[] | select(.name == "HTTPS_PROXY") | .value' <<<"$out")
  [[ "$v" == "http://proxy.example.com:3128" ]] || fail "$values: HTTPS_PROXY value is '$v'"
done

# Every OIDC_* name is refused with the chart's message, including names the
# chart does not generate in this layout.
for name in OIDC_CLIENT_ID OIDC_ISSUER_URL OIDC_USERNAME_CLAIM OIDC_USERNAME_PREFIX \
  OIDC_GROUPS_CLAIM OIDC_GROUPS_PREFIX OIDC_SIGNING_ALGS OIDC_SOMETHING_NEW; do
  for values in single-issuer multi-issuer; do
    if err=$(render -f "$CHART/ci/$values-values.yaml" --set "extraEnv[0].name=$name" --set 'extraEnv[0].value=x' 2>&1); then
      fail "$values: extraEnv.$name did not fail the render"
    fi
    grep -qF "extraEnv.$name: OIDC_* names belong to the chart. Set them through oidc.*" <<<"$err" \
      || fail "$values: extraEnv.$name failed with the wrong error: $err"
  done
done

# Entries without a name fail with their own message.
for bad in "extraEnv[0].value=x" "extraEnv[0]=HTTPS_PROXY"; do
  if err=$(render -f "$CHART/ci/single-issuer-values.yaml" --set "$bad" 2>&1); then
    fail "extraEnv entry without a name ($bad) did not fail"
  fi
  grep -qF 'each extraEnv entry must be an EnvVar map with at least a name' <<<"$err" \
    || fail "extraEnv entry without a name ($bad) failed with the wrong error: $err"
done

# extraEnv that is not a list (a map, or a string) fails with its own message.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
for doc in $'extraEnv:\n  HTTPS_PROXY:\n    name: HTTPS_PROXY\n    value: x\n' $'extraEnv: HTTPS_PROXY\n'; do
  printf '%s' "$doc" >"$tmp"
  if err=$(render -f "$CHART/ci/single-issuer-values.yaml" -f "$tmp" 2>&1); then
    fail "extraEnv that is not a list rendered: $doc"
  fi
  grep -qF 'extraEnv must be a list of EnvVar entries' <<<"$err" \
    || fail "extraEnv that is not a list failed with the wrong error: $err"
done

# The documented NO_PROXY value keeps the $(KUBERNETES_SERVICE_HOST) reference
# for Kubernetes to expand, and valueFrom entries pass through unchanged.
# shellcheck disable=SC2016 # $(KUBERNETES_SERVICE_HOST) is literal on purpose
out=$(render -f "$CHART/ci/single-issuer-values.yaml" \
  --set 'extraEnv[0].name=NO_PROXY' --set 'extraEnv[0].value=$(KUBERNETES_SERVICE_HOST)\,.svc\,.cluster.local' \
  --set 'extraEnv[1].name=HTTPS_PROXY' --set 'extraEnv[1].valueFrom.secretKeyRef.name=proxy' \
  --set 'extraEnv[1].valueFrom.secretKeyRef.key=url')
v=$(yq '.spec.template.spec.containers[0].env[] | select(.name == "NO_PROXY") | .value' <<<"$out")
# shellcheck disable=SC2016
[[ "$v" == '$(KUBERNETES_SERVICE_HOST),.svc,.cluster.local' ]] || fail "NO_PROXY rendered as '$v'"
ref=$(yq -o=json -I=0 '.spec.template.spec.containers[0].env[] | select(.name == "HTTPS_PROXY") | .valueFrom.secretKeyRef' <<<"$out")
[[ "$ref" == '{"key":"url","name":"proxy"}' ]] || fail "HTTPS_PROXY valueFrom.secretKeyRef rendered as '$ref'"
echo "chart extraEnv: ok"
