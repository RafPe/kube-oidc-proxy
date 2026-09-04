#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# The default render carries neither flag: an image pinned to a release older
# than the one that added --logging-format must still get a command line it can
# parse. The binary's own defaults (json, 0) apply when the chart says nothing.
out=$(helm template kop chart/kube-oidc-proxy --set oidc.issuerUrl=https://x --set oidc.clientId=y)
! grep -q -- '--logging-format' <<<"$out" || { echo "--logging-format rendered without logging.format set" >&2; exit 1; }
! grep -q -- '"--v=' <<<"$out" || { echo "--v rendered without logging.verbosity set" >&2; exit 1; }
out=$(helm template kop chart/kube-oidc-proxy --set oidc.issuerUrl=https://x --set oidc.clientId=y --set logging.format=text --set logging.verbosity=2)
grep -q -- '--logging-format=text' <<<"$out" || { echo "logging.format not rendered" >&2; exit 1; }
grep -q -- '--v=2' <<<"$out" || { echo "logging.verbosity not rendered" >&2; exit 1; }
# An explicit zero is a value, not an absence: it must render, or an operator
# cannot pin the default verbosity against a future change of it.
out=$(helm template kop chart/kube-oidc-proxy --set oidc.issuerUrl=https://x --set oidc.clientId=y --set logging.verbosity=0)
grep -q -- '--v=0' <<<"$out" || { echo "logging.verbosity=0 not rendered" >&2; exit 1; }
# A non-empty extraArgs must still render: the two flags above sit directly on top
# of the extraArgs range, whose whitespace trimming glued the first entry onto the
# preceding line until the range was rewritten.
helm template kop chart/kube-oidc-proxy --set oidc.issuerUrl=https://x --set oidc.clientId=y \
  --set extraArgs.v=5 --show-only templates/deployment.yaml >/dev/null
echo "chart logging values: ok"
