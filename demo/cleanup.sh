#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
#
# Tear down the demo: delete the kind cluster and remove generated artifacts.
set -euo pipefail

CLUSTER="kube-oidc-proxy-demo"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
  echo "==> Deleting kind cluster ${CLUSTER}"
  kind delete cluster --name "${CLUSTER}"
else
  echo "==> No kind cluster named ${CLUSTER} found; nothing to delete"
fi

rm -rf "${SCRIPT_DIR}/.generated"
echo "==> Done"
