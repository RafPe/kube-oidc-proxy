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

# Malformed authenticationConfig.content must fail the render, not silently
# grant nothing.
if helm template kop "$CHART" --set 'authenticationConfig.content=jwt: [' >/dev/null 2>&1; then
  echo "invalid authenticationConfig.content rendered instead of failing" >&2; exit 1
fi

echo "chart rbac userextras: ok"
