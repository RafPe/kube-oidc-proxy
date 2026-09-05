#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# The API server authorizes each Impersonate-Extra-<key> header as `impersonate`
# on `userextras/<key>`. The ClusterRole must therefore grant every extra key the
# proxy can emit: the claimMappings.extra keys declared in
# authenticationConfig.content plus rbac.userExtras. A key missing from the grant
# fails every request that carries it with 403.
CHART=chart/kube-oidc-proxy
render() { helm template kop "$CHART" "$@" --show-only templates/clusterrole.yaml; }

# Single-issuer mode declares no extras: no userextras beyond the fixed grant.
out=$(render --set oidc.issuerUrl=https://x --set oidc.clientId=y)
! grep -q -- 'userextras/github.com' <<<"$out" || { echo "userextras rendered without any extra keys" >&2; exit 1; }

# Inbound impersonation is authorized with a SubjectAccessReview the proxy
# creates itself; the ServiceAccount must be allowed to create them in every
# mode, or kubectl --as fails with 500 before any authorization happens.
grep -A4 -- '"authorization.k8s.io"' <<<"$out" | grep -q -- '"subjectaccessreviews"' \
  || { echo "ClusterRole does not grant subjectaccessreviews in authorization.k8s.io" >&2; exit 1; }
grep -A6 -- '"subjectaccessreviews"' <<<"$out" | grep -q -- '- "create"' \
  || { echo "subjectaccessreviews grant lacks the create verb" >&2; exit 1; }

# The multi-issuer fixture declares two extra keys on the GitHub issuer and one
# more via rbac.userExtras; all three must be granted, exactly once each.
out=$(render -f "$CHART/ci/multi-issuer-values.yaml")
for key in github.com/actor github.com/run-id example.com/team; do
  n=$(grep -c -- "\"userextras/${key}\"" <<<"$out" || true)
  [ "$n" = "1" ] || { echo "userextras/${key}: rendered ${n} times, expected 1" >&2; exit 1; }
done
# The grant carries the impersonate verb and nothing broader.
grep -A20 'userextras/example.com/team' <<<"$out" | grep -q -- '- "impersonate"' \
  || { echo "extra userextras rule lacks the impersonate verb" >&2; exit 1; }

# A key declared both in the config and in rbac.userExtras is granted once.
out=$(render -f "$CHART/ci/multi-issuer-values.yaml" --set 'rbac.userExtras={github.com/actor}')
n=$(grep -c -- '"userextras/github.com/actor"' <<<"$out" || true)
[ "$n" = "1" ] || { echo "duplicate key granted ${n} times, expected 1" >&2; exit 1; }

# The API server lowercases extra keys taken from headers before authorizing
# them, so a mixed-case rbac.userExtras entry must be granted in lowercase, and
# two spellings of one key must collapse to a single grant.
out=$(render --set oidc.issuerUrl=https://x --set oidc.clientId=y \
  --set 'rbac.userExtras={Example.com/Team,example.com/team}')
n=$(grep -c -- '"userextras/example.com/team"' <<<"$out" || true)
[ "$n" = "1" ] || { echo "mixed-case key: lowercase grant rendered ${n} times, expected 1" >&2; exit 1; }
! grep -q -- 'Example.com/Team' <<<"$out" || { echo "mixed-case key granted verbatim" >&2; exit 1; }

# extraImpersonationHeaders.headers adds Impersonate-Extra-<key> to every
# impersonated request, so its keys must be granted too; values and repeated
# keys must not leak into the grant.
out=$(render --set oidc.issuerUrl=https://x --set oidc.clientId=y \
  --set 'extraImpersonationHeaders.headers=example.com/env=prod\,example.com/env=eu\,Example.com/Tier=a=b')
for key in example.com/env example.com/tier; do
  n=$(grep -c -- "\"userextras/${key}\"" <<<"$out" || true)
  [ "$n" = "1" ] || { echo "extra header key ${key}: rendered ${n} times, expected 1" >&2; exit 1; }
done
! grep -q -- 'prod\|userextras/eu\|a=b' <<<"$out" || { echo "extra header value leaked into the grant" >&2; exit 1; }

# `helm upgrade --reuse-values` renders with the previous release's stored
# values and does not merge this chart's defaults, so a release installed
# before `rbac` existed renders with .Values.rbac nil. Nulling the key
# reproduces that; the render must succeed and still grant the config's keys.
out=$(render -f "$CHART/ci/multi-issuer-values.yaml" --set 'rbac=null') \
  || { echo "render failed with rbac unset (--reuse-values from an older release)" >&2; exit 1; }
grep -q -- '"userextras/github.com/actor"' <<<"$out" \
  || { echo "config-declared key not granted when rbac is unset" >&2; exit 1; }
! grep -q -- 'example.com/team' <<<"$out" \
  || { echo "rbac.userExtras key granted although rbac is unset" >&2; exit 1; }

# Malformed authenticationConfig.content must fail the render, not silently
# grant nothing.
if helm template kop "$CHART" --set 'authenticationConfig.content=jwt: [' >/dev/null 2>&1; then
  echo "invalid authenticationConfig.content rendered instead of failing" >&2; exit 1
fi

echo "chart rbac userextras: ok"
