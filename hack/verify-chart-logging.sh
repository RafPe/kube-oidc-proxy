#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
out=$(helm template kop chart/kube-oidc-proxy --set oidc.issuerUrl=https://x --set oidc.clientId=y)
grep -q -- '--logging-format=json' <<<"$out" || { echo "missing --logging-format default" >&2; exit 1; }
out=$(helm template kop chart/kube-oidc-proxy --set oidc.issuerUrl=https://x --set oidc.clientId=y --set logging.format=text --set logging.verbosity=2)
grep -q -- '--logging-format=text' <<<"$out" || { echo "logging.format not rendered" >&2; exit 1; }
grep -q -- '--v=2' <<<"$out" || { echo "logging.verbosity not rendered" >&2; exit 1; }
# A non-empty extraArgs must still render: the two flags above sit directly on top
# of the extraArgs range, whose whitespace trimming glued the first entry onto the
# preceding line until the range was rewritten.
helm template kop chart/kube-oidc-proxy --set oidc.issuerUrl=https://x --set oidc.clientId=y \
  --set extraArgs.v=5 --show-only templates/deployment.yaml >/dev/null
echo "chart logging values: ok"
