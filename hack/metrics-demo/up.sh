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

# Build the metrics demo: a kind cluster running kube-prometheus-stack, the
# e2e suite's mock OIDC issuer, and this chart installed with metrics, a
# ServiceMonitor and the dashboards. Every step is idempotent, so re-running
# after a failure resumes rather than starting over. Ends by asserting the
# state it must leave behind (check.sh).
#
# Pinned versions. Never "latest": a demo that drifts is not reproducible, and
# the screenshots in docs/dashboards were taken against exactly these.
KPS_VERSION=89.2.2
NODE_VERSION=1.37.0
# The kind node image the e2e suite already uses, from
# test/e2e/versions/kubernetes-versions.json, which pins images by digest.
NODE_IMAGE_DIGEST=sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
NODE_IMAGE="kindest/node:v${NODE_VERSION}@${NODE_IMAGE_DIGEST}"

# The kind the repository pins, not the one on PATH: kind's CLI is the only
# thing that decides which kubeadm config API version the node is initialised
# with, and a CLI older than the node image fails with "your configuration
# file uses an old API spec: kubeadm.k8s.io/v1beta3". go.mod pins
# sigs.k8s.io/kind v0.33.0, which is the version
# test/e2e/versions/kubernetes-versions.json names beside the node digest
# above, and the version the e2e suite already drives as a library. Needs Go,
# not a kind CLI.
KIND=(go run sigs.k8s.io/kind)

CLUSTER=kube-oidc-proxy-metrics-demo
STATE=hack/metrics-demo/.state
ISSUER_IMAGE=oidc-issuer-e2e
ARCH=$(go env GOARCH)

mkdir -p "$STATE"
KUBECONFIG=$STATE/kubeconfig; export KUBECONFIG

step() { echo; echo "==> $*"; }

step "kind cluster $CLUSTER (node $NODE_IMAGE)"
if "${KIND[@]}" get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "cluster already exists; exporting its kubeconfig"
  "${KIND[@]}" export kubeconfig --name "$CLUSTER" --kubeconfig "$STATE/kubeconfig"
else
  "${KIND[@]}" create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --kubeconfig "$STATE/kubeconfig"
fi

step "build and load the proxy image"
make build
# The tag names the build that was just produced, and is never constant:
# `helm upgrade --install` restarts pods only when something in the pod
# template changes, so a tag that repeats leaves the previous build serving
# under a freshly side-loaded image nobody is running. Derived after the build,
# not before: `make build` runs `generate` first, and the ldflags that stamp
# build_info are expanded inside that recipe, so a tree sampled beforehand can
# describe a different version from the one the binary reports.
# shellcheck source=hack/metrics-demo/imagetag.sh
. hack/metrics-demo/imagetag.sh
demo_build_identity METRICS_DEMO_IMAGE_TAG METRICS_DEMO_VERSION "bin/$ARCH/kube-oidc-proxy"
# shellcheck disable=SC2154  # both are assigned by demo_build_identity's printf -v.
PROXY_IMAGE=kube-oidc-proxy:$METRICS_DEMO_IMAGE_TAG
# check.sh reads these back, so a standalone run compares the running pods
# against what was actually deployed rather than against whatever the tree
# happens to describe by the time it runs.
printf '%s\n' "$METRICS_DEMO_IMAGE_TAG" >"$STATE/image-tag"
printf '%s\n' "$METRICS_DEMO_VERSION" >"$STATE/image-version"
echo "image $PROXY_IMAGE, reporting build_info version $METRICS_DEMO_VERSION"
# The Dockerfile copies bin/${TARGETARCH}/kube-oidc-proxy; BuildKit does not
# always populate TARGETARCH, so pass the host's explicitly (the kind node
# matches the host architecture).
docker build --build-arg "TARGETARCH=$ARCH" -t "$PROXY_IMAGE" .
"${KIND[@]}" load docker-image "$PROXY_IMAGE" --name "$CLUSTER"

step "build and load the mock issuer image $ISSUER_IMAGE"
# The same build test/kind/image.go's LoadIssuer performs: a static linux
# binary for the host architecture, into the Dockerfile's expected path.
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
  go build -o test/tools/issuer/bin/oidc-issuer-linux ./test/tools/issuer/cmd
docker build -t "$ISSUER_IMAGE" test/tools/issuer
"${KIND[@]}" load docker-image "$ISSUER_IMAGE" --name "$CLUSTER"

step "kube-prometheus-stack $KPS_VERSION"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null
helm repo update prometheus-community >/dev/null
helm upgrade --install kps prometheus-community/kube-prometheus-stack \
  --version "$KPS_VERSION" -n monitoring --create-namespace \
  -f hack/metrics-demo/kube-prometheus-stack-values.yaml --wait --timeout 15m

step "mock OIDC issuer, and the proxy's serving certificate"
kubectl create namespace proxy --dry-run=client -o yaml | kubectl apply -f -
# Idempotent: deploys the issuer only if it is not already there, and mints
# the proxy's serving certificate only if its Secret does not already exist.
go run ./hack/metrics-demo/issuer --state "$STATE" --namespace proxy

step "kube-oidc-proxy from this chart, with metrics"
helm upgrade --install kop ./chart/kube-oidc-proxy -n proxy \
  -f hack/metrics-demo/proxy-values.yaml \
  --set "oidc.issuerUrl=$(cat "$STATE/issuer-url")" \
  --set-file "oidc.caPEM=$STATE/issuer-ca.pem" \
  --set image.repository=kube-oidc-proxy \
  --set "image.tag=$METRICS_DEMO_IMAGE_TAG" \
  --set image.pullPolicy=Never \
  --wait --timeout 10m

step "RBAC and workload for the demo identities"
kubectl apply -f hack/metrics-demo/demo-identities.yaml
kubectl -n proxy rollout status deploy/kop-kube-oidc-proxy --timeout=5m
kubectl -n proxy wait --for=condition=Ready pod/demo-shell --timeout=5m

step "check"
bash hack/metrics-demo/check.sh
