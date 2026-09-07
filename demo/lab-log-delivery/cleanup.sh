#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
#
# Remove the lab's pieces from the demo cluster: the agent and the emulator.
# The proxy keeps its audit flags (harmless). ../cleanup.sh deletes the cluster.
set -euo pipefail

CTX="kind-kube-oidc-proxy-demo"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if kubectl --context "${CTX}" get ns >/dev/null 2>&1; then
  echo "==> Uninstalling aws-for-fluent-bit"
  helm --kube-context "${CTX}" uninstall aws-for-fluent-bit -n aws-for-fluent-bit >/dev/null 2>&1 || true
  echo "==> Deleting namespaces aws-for-fluent-bit and floci (waits, so run.sh can follow immediately)"
  kubectl --context "${CTX}" delete ns aws-for-fluent-bit floci --ignore-not-found --timeout=180s >/dev/null
else
  echo "==> Cluster ${CTX} not reachable; nothing to remove"
fi

rm -rf "${SCRIPT_DIR}/.generated"
echo "==> Done"
