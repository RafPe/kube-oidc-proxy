#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# Delete the demo cluster and everything up.sh generated. Safe to run at any
# time, including when nothing was ever created.
# The kind the repository pins (go.mod, sigs.k8s.io/kind), not the CLI on
# PATH; see the comment in up.sh. Needs Go, not a kind CLI.
KIND=(go run sigs.k8s.io/kind)

CLUSTER=kube-oidc-proxy-metrics-demo
STATE=hack/metrics-demo/.state

"${KIND[@]}" delete cluster --name "$CLUSTER"
rm -rf "$STATE"
echo "metrics demo: torn down"
