# kube-oidc-proxy multi-issuer demo

A local, one-command demo that proves kube-oidc-proxy's headline feature:
**multi-issuer authentication**. A single proxy is configured with a Kubernetes
`AuthenticationConfiguration` that trusts **two** independent OIDC issuers, and
tokens from *either* issuer authenticate through it and are impersonated to the
Kubernetes API server as distinct users.

Everything runs locally in a [kind](https://kind.sigs.k8s.io/) cluster. No cloud
accounts, no DNS, no browser.

- [What it shows](#what-it-shows)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Poking at it after a run](#poking-at-it-after-a-run)
- [Troubleshooting](#troubleshooting)
- [Layout](#layout)

## What it shows

```
                         ┌──────────────────────────────┐
  alice@example.com ───► │ dex-a (issuer A)              │
  (password grant)       │ https://dex-a.dex.svc...:5556 │──┐
                         └──────────────────────────────┘  │  id_token A
                                                            ▼
                                              ┌─────────────────────────┐      impersonate
   kubectl (token A) ───────────────────────►│                         │────► kube-apiserver
                                              │     kube-oidc-proxy     │      as
   kubectl (token B) ───────────────────────►│  --authentication-config│────► oidc-a:alice@example.com
                                              │   (issuer A + issuer B) │      oidc-b:bob@example.com
                                                            ▲
                         ┌──────────────────────────────┐  │  id_token B
  bob@example.com ─────► │ dex-b (issuer B)              │──┘
  (password grant)       │ https://dex-b.dex.svc...:5556 │
                         └──────────────────────────────┘
```

- Two Dex issuers, each with its own TLS-served OIDC discovery endpoint and one
  static user (`alice@example.com` on A, `bob@example.com` on B).
- One kube-oidc-proxy, deployed with the Helm chart in
  [`chart/kube-oidc-proxy`](../chart/kube-oidc-proxy), running in
  multi-issuer mode via `authenticationConfig.content`
  (`apiserver.config.k8s.io/v1`), with `readinessRequireAllIssuers: true` so the
  pod is only Ready once **both** issuers have initialized (JWKS fetched).
- A token minted from issuer A authenticates as `oidc-a:alice@example.com`; a
  token from issuer B authenticates as `oidc-b:bob@example.com` — through the
  *same* proxy. That is the multi-issuer proof.

## Prerequisites

Install and have on your `PATH`: `kind`, `docker` (daemon running), `kubectl`,
`helm` (verified with v4; v3.8+ should also work), `openssl`, `jq`, `curl`, and
the Go toolchain (`go`, to build the proxy binary). The demo builds the proxy
image from your checkout rather than pulling a published release, so it
exercises the code you have, including uncommitted changes.

## Usage

Both scripts locate their own files, so they work from any directory. The
commands on this page are written for the repository root:

```sh
demo/run.sh       # build, deploy, and verify (leaves the cluster running)
demo/cleanup.sh   # delete the kind cluster and generated artifacts
```

`run.sh` is idempotent: if a `kube-oidc-proxy-demo` cluster already exists it is
deleted and recreated. On success it prints, for each issuer, a successful
`kubectl get pods -A` and a denied `kubectl get secrets -A` whose error names the
impersonated user — unambiguous proof of which identity the proxy asserted.

## How it works

`run.sh` performs these steps:

1. **Build the image.** Compiles the proxy (`go build` for linux amd64+arm64,
   the same outputs as `make build` minus the test-only code generation), builds
   `kube-oidc-proxy:demo` from the repo `Dockerfile`, and `kind load`s it. The
   chart is deployed with `image.pullPolicy=Never` so the cluster never reaches
   for a registry.
2. **Create the cluster.** `kind create cluster --name kube-oidc-proxy-demo`.
3. **Generate certificates.** One CA plus a serving certificate per Dex, whose
   SANs cover the in-cluster Service DNS (`dex-a.dex.svc.cluster.local`,
   `dex-a.dex`, `dex-a`). Generated material lives in the gitignored
   `.generated/` directory.
4. **Deploy the two Dex issuers** (namespace `dex`) from
   [`manifests/dex.yaml.tpl`](manifests/dex.yaml.tpl). Each Dex's `issuer:` is
   set to exactly its Service DNS URL so its discovery document's `iss` matches
   what the proxy dials. The password grant (`oauth2.passwordConnector: local`
   + `enablePasswordDB: true`) lets a token be minted with a single `curl` — no
   browser redirect.
5. **Install the proxy** via Helm. The CA of each issuer is inlined into
   [`manifests/authentication-config.yaml.tpl`](manifests/authentication-config.yaml.tpl)
   under `issuer.certificateAuthority`; the rendered file is passed to the chart
   with `--set-file authenticationConfig.content=...`. The username is the
   token's `email` claim, prefixed `oidc-a:` / `oidc-b:` per issuer.
6. **Apply demo RBAC** ([`manifests/rbac.yaml`](manifests/rbac.yaml)): a
   `ClusterRoleBinding` granting each impersonated username the built-in `view`
   ClusterRole. The proxy's own ServiceAccount already holds the impersonation
   RBAC granted by the chart.
7. **Mint and verify.** For each issuer it port-forwards Dex, mints an ID token
   via the password grant (`--resolve` keeps SNI/cert/issuer consistent with the
   Service DNS), then port-forwards the proxy and runs `kubectl` with a
   kubeconfig whose bearer token is the minted `id_token`.

### Credentials (demo only)

| Issuer | Username            | Password   | Impersonated as             |
|--------|---------------------|------------|-----------------------------|
| dex-a  | `alice@example.com` | `password` | `oidc-a:alice@example.com`  |
| dex-b  | `bob@example.com`   | `password` | `oidc-b:bob@example.com`    |

OAuth client: `demo` / `demo-client-secret`. These are throwaway demo values.

### A note on TLS verification

The kubeconfig used to call the proxy sets `insecure-skip-tls-verify: true`. The
proxy's *own* serving certificate is a self-signed cert generated by the chart,
and this is a local demo — so client-to-proxy TLS is not verified. This does
**not** weaken the OIDC path: the proxy verifies each Dex's certificate against
the CA inlined in the AuthenticationConfiguration, and verifies every token's
signature against the issuer's JWKS. In production, front the proxy with a
properly issued serving certificate and drop `insecure-skip-tls-verify`.

## Poking at it after a run

The cluster is left running. To explore manually:

```sh
# Mint a token from issuer A (alice):
kubectl --context kind-kube-oidc-proxy-demo -n dex port-forward svc/dex-a 5556:5556 &
TOKEN=$(curl -s --resolve dex-a.dex.svc.cluster.local:5556:127.0.0.1 \
  --cacert demo/.generated/certs/ca.crt \
  https://dex-a.dex.svc.cluster.local:5556/dex/token \
  -d grant_type=password -d scope="openid email groups" \
  -d client_id=demo -d client_secret=demo-client-secret \
  -d username=alice@example.com -d password=password | jq -r .id_token)

# Call the API server through the proxy as that user:
kubectl --context kind-kube-oidc-proxy-demo -n kube-oidc-proxy port-forward svc/kube-oidc-proxy 8443:443 &
kubectl --server https://127.0.0.1:8443 --insecure-skip-tls-verify \
  --token "$TOKEN" get pods -A
```

## Troubleshooting

- **Proxy pod never becomes Ready.** With `readinessRequireAllIssuers: true` the
  proxy waits until it has fetched JWKS from *both* Dex issuers. Check it reached
  them:
  `kubectl --context kind-kube-oidc-proxy-demo -n kube-oidc-proxy logs deploy/kube-oidc-proxy`.
  A discovery/`iss` mismatch means a Dex `issuer:` value does not equal its
  Service DNS URL.
- **`get pods` is Forbidden.** RBAC did not match the impersonated username. The
  name must be exactly `oidc-a:alice@example.com` / `oidc-b:bob@example.com`
  (the `email` claim plus the per-issuer prefix). Confirm with the (expected)
  `get secrets` error, which prints the username the proxy asserted.
- **Token mint returns null.** Dex was not ready, or the CA/`--resolve` host does
  not match the serving cert SAN. The mint uses the Service DNS name via
  `--resolve` on purpose so SNI, certificate, and `iss` all line up.
- **Port-forward errors.** Re-run `./run.sh`; it recreates the cluster cleanly.
  Stray port-forwards from a crashed run are killed on the script's exit trap.

## Layout

```
demo/
├── run.sh                                  # orchestrates build, deploy, verify
├── cleanup.sh                              # kind delete cluster + rm .generated
├── manifests/
│   ├── dex.yaml.tpl                        # Dex ConfigMap/Deployment/Service (rendered per issuer)
│   ├── authentication-config.yaml.tpl      # multi-issuer AuthenticationConfiguration (CA inlined at runtime)
│   ├── proxy-values.yaml                   # Helm values for the proxy
│   └── rbac.yaml                           # view ClusterRoleBindings for the two identities
└── .generated/                             # gitignored: certs, rendered config, kubeconfigs
```
