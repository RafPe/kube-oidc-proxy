#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# Every path below - the chart, the values files, the state directory - is
# relative to the repository root, so anchor there instead of trusting the
# caller's working directory. Run from anywhere else the first thing to fail
# was the state check, reporting "missing hack/metrics-demo/.state/..." about
# a demo that was in fact up. The sourced helpers below are named relatively
# too, so this has to come first.
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Delete the demo cluster and everything up.sh generated. Safe to run at any
# time, including when nothing was ever created, and the generated state goes
# whatever happens to the cluster: `kind delete cluster` fails outright when
# Docker is not running, and under `set -e` that used to skip the removal
# below, leaving the mock issuer's private key and a kubeconfig behind while
# the file claimed the demo had been torn down. The removal is a trap, so it
# runs on the failure path too; the failure is still reported and still exits
# non-zero.
# The kind the repository pins (go.mod, sigs.k8s.io/kind), not the CLI on
# PATH; see the comment in up.sh. Needs Go, not a kind CLI.
KIND=(go run sigs.k8s.io/kind)

CLUSTER=kube-oidc-proxy-metrics-demo
STATE=hack/metrics-demo/.state

trap 'rm -rf "$STATE"' EXIT

"${KIND[@]}" delete cluster --name "$CLUSTER"
echo "metrics demo: torn down"
