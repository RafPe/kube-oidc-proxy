# Operations

Security, troubleshooting, and testing the proxy locally.

## Security

- **The proxy is a privileged component.** Its ServiceAccount can impersonate
  users, groups, and extras against the API server. Restrict who can modify its
  Deployment and RBAC, and keep the chart's hardened defaults (non-root,
  read-only root filesystem, dropped capabilities, seccomp `RuntimeDefault`).
- **Impersonation replaces, but does not bypass, RBAC.** The API server still
  authorizes the impersonated identity. Keep API-server RBAC tight; the proxy
  decides *who* the request is, not *what* they may do.
- **Terminate and verify TLS end to end.** Clients must trust the proxy's
  serving certificate, and each OIDC issuer's TLS must be verifiable
  (`oidc.caPEM` / inline `certificateAuthority` for private CAs).
- **Scope audiences and required claims.** Use `audiences` / `--oidc-client-id`
  and `requiredClaims` so tokens minted for other systems can't be replayed
  against the cluster — especially for machine issuers like GitHub Actions.
- **Mind username prefixes across issuers.** In multi-issuer mode, distinct
  `prefix` values stop one issuer's `alice` from colliding with another's.
- **Use token passthrough deliberately.** `--token-passthrough` forwards
  non-OIDC tokens after a TokenReview; only enable it (and constrain
  `--token-passthrough-audiences`) when you understand the tokens involved.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Pod never becomes Ready in multi-issuer mode | With `readinessRequireAllIssuers: true`, **all** issuers must fetch their JWKS. Check pod logs for the per-issuer initialization messages and confirm each issuer URL is reachable and serves a valid discovery/JWKS document. Set it to `false` to become ready on the first issuer. |
| `authentication-config and --oidc-* flags are mutually exclusive` | You set both `authenticationConfig.content` and one or more `oidc.*` values. Pick one mode. |
| `401 Unauthorized` from the proxy | The token failed OIDC validation — wrong `issuerUrl`/`clientId` (audience), expired token, unmet `requiredClaims`, or a signing algorithm not in `--oidc-signing-algs`. Look for an `AuFail` line in the proxy logs. |
| `403 Forbidden` after a successful login | Authentication worked but RBAC denied the impersonated identity. Grant the mapped username/groups the appropriate roles. Watch for username **prefixes** (e.g. `google:alice@example.com`). |
| `kubectl --as` fails through the proxy | The authenticated user isn't authorized to impersonate that identity (`SubjectAccessReview` denied), or the proxy's ServiceAccount lacks impersonation RBAC for a named `Impersonate-Extra-` key. |
| TLS errors connecting to the proxy | The client's kubeconfig `certificate-authority` must trust the proxy's **serving** certificate (self-signed by the chart, your own Secret, or cert-manager). |
| Confirm which issuers loaded | `kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy \| grep "configured OIDC issuers"`. |

### Reading the request log

The proxy logs every request to stdout so a SIEM (via fluentd or similar) can
ingest them. A successful authentication looks like:

```
[2021-11-25T01:05:17+0000] AuSuccess src:[10.42.0.5 / 10.42.1.3, 10.42.0.5] URI:/api/v1/namespaces/openunison/pods?limit=500 inbound:[mlbadmin1 / system:masters|system:authenticated /]
```

- The bracketed prefix is an ISO-8601 timestamp.
- `AuSuccess` indicates authentication succeeded (`AuFail` on failure).
- `src` is the remote address, followed by the `X-Forwarded-For` value if present.
- `URI` is the request path.
- `inbound` is the username, groups, and extra info taken from the JWT.

When impersonation headers are present, an `outbound` section is appended showing
the impersonated identity:

```
[2021-11-25T01:05:17+0000] AuSuccess src:[10.42.0.5 / 10.42.1.3] URI:/api/v1/namespaces/openunison/pods?limit=500 inbound:[mlbadmin1 / system:masters|system:authenticated /] outbound:[mlbadmin2 / group2|system:authenticated /]
```

A failure omits the token information:

```
[2021-11-25T01:05:24+0000] AuFail src:[10.42.0.5 / 10.42.1.3] URI:/api/v1/nodes
```

## Development and testing

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
`KUBE_OIDC_PROXY_K8S_VERSION` (kind node image version).

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

Commit `.github/workflows/oidc.yaml` and push:

```yaml
name: mint-oidc-token
on: workflow_dispatch
permissions:
  id-token: write
jobs:
  mint:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/github-script@v7
      with:
        script: |
          const t = await core.getIDToken('kube-oidc-proxy-kind-test')
          require('fs').writeFileSync('token.jwt', t)
    - uses: actions/upload-artifact@v4
      with:
        name: oidc-token
        path: token.jwt
        retention-days: 1
```

> ⚠️ The artifact briefly holds a live token. It expires after ~5 minutes and
> only grants what your **local test cluster's** RBAC allows, but treat it as a
> secret all the same.

### 2. Build the image and create the cluster

```bash
docker build -t kube-oidc-proxy:test .
kind create cluster --name oidc-test
kind load docker-image kube-oidc-proxy:test --name oidc-test
```

### 3. Deploy the chart

This uses the simple `sub`-as-username mapping. For CEL alternatives (readable
usernames, `claimValidationRules`, numeric-ID hardening), see the
[multi-issuer guide](./multi-issuer.md#github-actions).

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

helm install kube-oidc-proxy ./chart/kube-oidc-proxy \
  -n kube-oidc-proxy --create-namespace -f /tmp/values-test.yaml
kubectl -n kube-oidc-proxy rollout status deploy/kube-oidc-proxy --timeout=180s

# The proxy lists its issuers at startup:
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy | grep "configured OIDC issuers"
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
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy --tail=20   # AuSuccess / AuFail
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

## See also

- [Multi-issuer authentication](./multi-issuer.md)
- [Configuration reference](./configuration.md)
- [Getting started](./getting-started.md)
- [Architecture](./architecture.md)
