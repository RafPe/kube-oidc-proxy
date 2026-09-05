# Development and testing

Building the proxy, running it against a local cluster, the end-to-end suite,
and a local multi-issuer test against a real GitHub Actions token. For running
the proxy in production see [operations](./operations.md).

- [Build and test](#build-and-test)
  - [Local dev cluster](#local-dev-cluster)
  - [End-to-end tests](#end-to-end-tests)
- [Local multi-issuer test: kind and GitHub Actions](#local-multi-issuer-test-kind-and-github-actions)
  - [Prerequisites](#prerequisites)
  - [1. Token-minting workflow (one-time)](#1-token-minting-workflow-one-time)
  - [2. Build the image and create the cluster](#2-build-the-image-and-create-the-cluster)
  - [3. Deploy the chart](#3-deploy-the-chart)
  - [4. RBAC](#4-rbac)
  - [5. Mint a token and fetch it (TTL ~5 min — move fast)](#5-mint-a-token-and-fetch-it-ttl-5-min--move-fast)
  - [6. Test through the proxy](#6-test-through-the-proxy)
  - [7. Access logs and cleanup](#7-access-logs-and-cleanup)
  - [Adding the next system](#adding-the-next-system)
- [Chart checks](#chart-checks)
- [Log contract](#log-contract)
- [Architecture diagrams](#architecture-diagrams)
- [See also](#see-also)

## Build and test

Building `kube-oidc-proxy` requires Go 1.26 or higher.

### Local dev cluster

A few `make` targets spin up a kind cluster for quick testing:

- `make dev_cluster_create` — create a kind cluster and build/load the proxy and
  tooling images onto each node.
- `make dev_cluster_deploy` — build, load, and deploy the proxy alongside a fake
  OIDC issuer, reachable via a NodePort service. It prints a signed OIDC token
  valid for the proxy, which you can use directly:

  ```bash
  curl -k https://<node-ip>:<nodeport> -H 'Authorization: bearer <token>'
  ```

  Set `KUBE_OIDC_PROXY_FAKE_APISERVER=true make dev_cluster_deploy` to also
  deploy a fake API server that logs the headers and request body the proxy
  sends — useful for inspecting impersonation output.
- `make dev_cluster_destroy` — delete the test cluster.

### End-to-end tests

`make e2e` runs the Go end-to-end suite (`test/e2e/suite`) against a real
Kubernetes cluster. It's hermetic: it builds the proxy and test-tool images from
source, creates its own [kind](https://kind.sigs.k8s.io) cluster, loads the
images, runs the suite, and tears the cluster down on exit (including on failure
or interrupt). No pre-existing cluster is required.

Prerequisites (all on `PATH`): `go`, `docker` (daemon running), `kind`,
`kubectl`. Images are built for the host architecture, so the suite runs on both
`amd64` and `arm64` (e.g. Apple Silicon).

```sh
make e2e          # build images, spin up kind, run the suite, tear down
make e2e-clean    # delete a leftover e2e kind cluster (safe if none exists)
```

Useful overrides: `E2E_TIMEOUT` (Go test timeout, default `30m`) and
`KUBE_OIDC_PROXY_K8S_VERSION`, which selects among the versions declared in
`test/e2e/versions/kubernetes-versions.json` (default: the newest). Versions
outside the manifest are refused — the manifest is the definition of what
this commit supports. CI tests the newest declared version on every pull
request and the full declared window on the twice-daily scheduled run.

The suite runs in CI on every pull request and on pushes to `main`
(`.github/workflows/e2e.yaml`). A companion workflow
(`.github/workflows/e2e-oidc-gha.yaml`) proves the multi-issuer union
authenticator against the **real** GitHub Actions OIDC issuer alongside a local
Dex issuer. For a scripted multi-issuer demo, see [`../demo/README.md`](../demo/README.md).

## Local multi-issuer test: kind and GitHub Actions

This runs the proxy in a local [kind](https://kind.sigs.k8s.io/) cluster and
authenticates with a **real GitHub Actions OIDC token**. GitHub only mints these
tokens inside a workflow run, so the flow is:

```text
GitHub Actions (mint token, TTL ~5 min)
        │  gh run download
        ▼
local terminal ── kubectl --token=... ──► kube-oidc-proxy (kind)
                                              │ validates JWT against
                                              │ token.actions.githubusercontent.com
                                              ▼ impersonates mapped identity
                                          kind API server ── RBAC decides
```

### Prerequisites

- `docker`, `kind`, `helm`, `kubectl`, `gh` (authenticated: `gh auth status`).
- Set these once per shell — every `gh` call needs an explicit `--repo`:

```bash
export GH_SLUG="rafpe/kube-oidc-proxy"   # <owner>/<repo> hosting the mint workflow
export BRANCH="master"
```

### 1. Token-minting workflow (one-time)

You need a `workflow_dispatch` workflow in the repository that requests an ID
token (`permissions: id-token: write`, then `core.getIDToken(<audience>)`)
and uploads it as a short-lived artifact.

> [!NOTE]
> This repository's own [`.github/workflows/oidc.yaml`](../.github/workflows/oidc.yaml)
> is a minimal example to copy from. The audience it requests
> (`kube-oidc-proxy-kind-test`) is the one the proxy config in step 3 expects;
> the two must match.

> [!WARNING]
> The artifact briefly holds a live token. It expires after ~5 minutes and only
> grants what your **local test cluster's** RBAC allows, but treat it as a
> secret all the same.

### 2. Build the image and create the cluster

```bash
docker build -t kube-oidc-proxy:test .
kind create cluster --name oidc-test
kind load docker-image kube-oidc-proxy:test --name oidc-test
```

### 3. Deploy the chart

This uses the simple `sub`-as-username mapping, which is enough to prove the
flow. The mapping to run in production, with a stable username, trust tiers,
audit extras and numeric-ID pinning, is the
[GitHub Actions recipe](./integrations.md#github-actions).

```bash
cat > /tmp/values-test.yaml <<'EOF'
image:
  repository: kube-oidc-proxy
  tag: test
  pullPolicy: Never

authenticationConfig:
  content: |
    apiVersion: apiserver.config.k8s.io/v1
    kind: AuthenticationConfiguration
    jwt:
    - issuer:
        url: https://token.actions.githubusercontent.com
        audiences: ["kube-oidc-proxy-kind-test"]
      claimMappings:
        # GitHub's newer sub is ID-embedded: repo:Owner@<owner_id>/repo@<repo_id>:ref:...
        username:
          claim: sub
          prefix: "gha:"
        # GitHub tokens carry no groups claim — CEL synthesizes one from
        # repository_owner (case-sensitive: "RafPe" != "rafpe"):
        groups:
          expression: '["github:" + claims.repository_owner]'
EOF

helm install kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  -n kube-oidc-proxy --create-namespace -f /tmp/values-test.yaml
kubectl -n kube-oidc-proxy rollout status deploy/kube-oidc-proxy --timeout=180s

# The proxy lists its issuers at startup, then reports each one initialized:
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy \
  | jq -r 'select(.event_type | startswith("oidc.issuer.")) | [.event_type, .issuer_name] | @tsv'
```

To change config later, edit the values file and `helm upgrade kube-oidc-proxy
./chart/kube-oidc-proxy -n kube-oidc-proxy -f /tmp/values-test.yaml` — the
checksum annotation rolls the pods automatically.

### 4. RBAC

Decode a token first (step 5) if you're unsure of your exact claims. With the
default `sub` mapping and GitHub's ID-embedded subject format:

```bash
# Group binding — matches the CEL-synthesized group (mind the case!):
kubectl create clusterrolebinding gha-owner-view \
  --clusterrole=view --group="github:RafPe"

# Exact-subject binding — GitHub's sub embeds owner/repo IDs:
kubectl create clusterrolebinding gha-branch-view \
  --clusterrole=view \
  --user="gha:repo:RafPe@9809655/kube-oidc-proxy@1308696420:ref:refs/heads/master"
```

### 5. Mint a token and fetch it (TTL ~5 min — move fast)

```bash
gh workflow run oidc.yaml --repo "$GH_SLUG" --ref "$BRANCH"
sleep 5
RUN_ID=$(gh run list --repo "$GH_SLUG" --workflow=oidc.yaml -L1 \
  --json databaseId -q '.[0].databaseId')
gh run watch "$RUN_ID" --repo "$GH_SLUG"
rm -rf /tmp/oidc && gh run download "$RUN_ID" --repo "$GH_SLUG" \
  -n oidc-token -D /tmp/oidc
TOKEN=$(cat /tmp/oidc/token.jwt)

# Inspect the claims you are about to authenticate with:
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null \
  | jq '{iss,aud,sub,repository,repository_owner,ref}'
```

### 6. Test through the proxy

```bash
kubectl -n kube-oidc-proxy port-forward svc/kube-oidc-proxy 8443:443 &
sleep 3
```

Who does the cluster think you are?

```bash
kubectl --server=https://127.0.0.1:8443 --insecure-skip-tls-verify=true \
  --token="$TOKEN" auth whoami
```

Expected: your prefixed username plus groups `[github:RafPe, system:authenticated]`.
Then prove authorization scoping:

```bash
PROXY="--server=https://127.0.0.1:8443 --insecure-skip-tls-verify=true --token=$TOKEN"
kubectl $PROXY get pods -A        # allowed  (view)
kubectl $PROXY create ns nope     # forbidden (view cannot write)
```

If you get `401`, the token expired — rerun step 5. Steps 2–4 stay up.

> `--insecure-skip-tls-verify` is acceptable only against this throwaway kind
> cluster (the chart generated an ephemeral self-signed cert). Real deployments
> set `tls.secretName`/cert-manager and ship the CA in kubeconfig.

### 7. Access logs and cleanup

```bash
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy --tail=20   # request.access.decided: AuSuccess / AuFail
kill %1
kind delete cluster --name oidc-test
```

### Adding the next system

A pure config change — no new deployments:

1. Append another `jwt:` entry to `authenticationConfig.content` (its issuer
   URL, its own audience, and a **distinct prefix**, e.g. `sys-a:` — never reuse
   or omit prefixes across issuers).
2. Add RBAC bindings for the new prefixed identities.
3. `helm upgrade` — pods roll automatically; with the default readiness mode the
   rollout completes even if the new issuer is temporarily unreachable (it's
   logged as pending and starts working the moment its JWKS loads).

## Chart checks

Committed fixtures under `chart/kube-oidc-proxy/ci/` cover both authentication
configurations and are used by the `helm-chart` GitHub Actions workflow,
together with two scripts that pin down what the chart renders:

```sh
helm lint chart/kube-oidc-proxy -f chart/kube-oidc-proxy/ci/single-issuer-values.yaml
helm template t chart/kube-oidc-proxy -f chart/kube-oidc-proxy/ci/multi-issuer-values.yaml
bash hack/verify-chart-logging.sh   # logging values render as flags
bash hack/verify-chart-rbac.sh      # ClusterRole grants every declared userextras key
```

## Log contract

The event registry in [`pkg/logging/events.go`](../pkg/logging/events.go) is
the source for the [event table](./logging.md#event-registry) in the logging
reference; `make eventdoc` regenerates it and CI fails on a diff. Never
hand-edit between the `events:begin` and `events:end` markers. The rules that
keep saved queries working across releases are in
[logging: compatibility](./logging.md#compatibility).

## Architecture diagrams

The C4 diagrams under [`docs/c4/`](./c4/) are generated from
[`workspace.dsl`](./c4/workspace.dsl) with Structurizr; edit the DSL, not the
PNGs. [Architecture](./architecture.md#diagrams) shows them.

## See also

- [Operations](./operations.md) — running the proxy in production.
- [Releases](./releases.md) — how a merged change becomes a release.
- [Multi-issuer authentication](./multi-issuer.md) — the configuration the
  local test exercises.
