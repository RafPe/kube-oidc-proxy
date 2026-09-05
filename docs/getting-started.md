# Getting started

Deploy `kube-oidc-proxy` with the Helm chart, configure an authentication mode,
and point `kubectl` at it. The chart in
[`../chart/kube-oidc-proxy`](../chart/kube-oidc-proxy) creates the Deployment,
Service, ServiceAccount, and impersonation RBAC in a `kube-oidc-proxy`
namespace. The [chart README](../chart/kube-oidc-proxy/README.md) is the full
values reference.

- [Prerequisites](#prerequisites)
- [Install](#install)
  - [1. From the OCI registry (recommended)](#1-from-the-oci-registry-recommended)
  - [2. From a local checkout](#2-from-a-local-checkout)
  - [3. As raw manifests](#3-as-raw-manifests)
- [Choose an authentication mode](#choose-an-authentication-mode)
  - [Single-issuer](#single-issuer)
  - [Multi-issuer](#multi-issuer)
- [Serving TLS](#serving-tls)
- [Point kubectl at the proxy](#point-kubectl-at-the-proxy)
- [Next steps](#next-steps)

## Prerequisites

- A Kubernetes cluster and `kubectl`.
- [Helm](https://helm.sh) 3+ (developed and tested against Helm v4).
- One or more OIDC issuers that publish a discovery document and JWKS.
- Optional: [cert-manager](https://github.com/jetstack/cert-manager), to issue
  the proxy's serving certificate.

## Install

### 1. From the OCI registry (recommended)

```sh
helm install kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  --namespace kube-oidc-proxy --create-namespace \
  --set oidc.clientId=<client-id> \
  --set oidc.issuerUrl=https://<issuer-url> \
  --set oidc.usernameClaim=email
```

The chart and image are signed (cosign, keyless). Add `--version <x.y.z>` to pin
a specific [release](https://github.com/rafpe/kube-oidc-proxy/releases); omit it
for the latest.

### 2. From a local checkout

```sh
helm install kube-oidc-proxy ./chart/kube-oidc-proxy \
  --namespace kube-oidc-proxy --create-namespace \
  --set oidc.clientId=<client-id> \
  --set oidc.issuerUrl=https://<issuer-url> \
  --set oidc.usernameClaim=email
```

### 3. As raw manifests

Prefer plain YAML for `kubectl apply` or GitOps? Render it from the chart:

```sh
helm template kube-oidc-proxy ./chart/kube-oidc-proxy \
  --namespace kube-oidc-proxy -f my-values.yaml > kube-oidc-proxy.yaml
kubectl apply -f kube-oidc-proxy.yaml
```

## Choose an authentication mode

The proxy has two **mutually exclusive** modes — configure exactly one.

| Mode | Enable with | Flags used |
| --- | --- | --- |
| **Single-issuer** | `oidc.clientId`, `oidc.issuerUrl`, `oidc.usernameClaim` | `--oidc-*` |
| **Multi-issuer** (headline feature) | `authenticationConfig.content` | `--authentication-config` |

> [!WARNING]
> The binary refuses to start when both `--authentication-config` and
> issuer-specific `--oidc-*` flags are given. The chart never produces that
> combination: while `authenticationConfig.content` is set it passes
> `--authentication-config` and does not render the issuer-specific `oidc.*`
> values. `oidc.tlsClient` is the exception; it applies to every issuer in
> either mode.

### Single-issuer

```yaml
oidc:
  clientId: my-client
  issuerUrl: https://accounts.google.com
  usernameClaim: email
  groupsClaim: groups          # optional: claim carrying the user's groups
  requiredClaims:              # optional: claims that MUST match
    hd: example.com
```

If the issuer's TLS certificate comes from a private CA, supply it inline:

```yaml
oidc:
  clientId: my-client
  issuerUrl: https://oidc.internal.example.com
  usernameClaim: email
  caPEM: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
```

See the [CLI reference](./configuration.md#cli-reference) for the full set of
single-issuer `--oidc-*` knobs (prefixes, signing algorithms, required claims).

### Multi-issuer

Accept tokens from several identity providers at once via a Kubernetes
`AuthenticationConfiguration`. This is the fork's headline feature — the
[multi-issuer guide](./multi-issuer.md) walks through it end to end.

## Serving TLS

The proxy terminates TLS for its clients. Provide its serving certificate one of
three ways.

**Self-signed (default).** With no TLS values set, the chart generates a
self-signed certificate. Good for a quick start; clients must trust the
generated CA.

**cert-manager.** Let [cert-manager](https://github.com/jetstack/cert-manager)
issue it:

```yaml
tls:
  certManager: true
  selfSigned: true          # create a self-signed Issuer
  # selfSigned: false
  # issuerName: my-issuer   # ...or reference your own Issuer
```

**Your own Secret.** Reference an existing `kubernetes.io/tls` Secret:

```yaml
tls:
  secretName: my-tls-secret-with-key-and-cert
```

## Point kubectl at the proxy

Once the proxy Service has an address, hand users a kubeconfig that talks to
`kube-oidc-proxy` instead of the API server directly. For interactive logins,
use [kubelogin](https://github.com/int128/kubelogin) (`kubectl oidc-login`) —
a credential exec plugin that runs the OIDC flow in the browser, then caches
and refreshes the ID token automatically:

```sh
kubectl krew install oidc-login   # or: brew install kubelogin
```

```yaml
apiVersion: v1
clusters:
  - cluster:
      certificate-authority: /path/to/proxy-ca.pem  # the proxy's serving CA
      server: https://<proxy-address>:443
    name: my-cluster
contexts:
  - context:
      cluster: my-cluster
      user: my-oidc-user
    name: my-cluster
current-context: my-cluster
kind: Config
users:
  - name: my-oidc-user
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl
        args:
          - oidc-login
          - get-token
          - --oidc-issuer-url=https://<issuer-url>
          - --oidc-client-id=<client-id>
          - --oidc-client-secret=<client-secret>  # omit for public clients
        interactiveMode: IfAvailable
```

Already minting ID tokens another way (CI, a script, a non-interactive flow)?
Pass one directly instead: `kubectl --token=<id-token> get pods`.

> [!TIP]
> No OIDC identity provider yet? The [multi-issuer demo](../demo/README.md)
> stands up a complete end-to-end setup — two Dex issuers and the proxy in a
> local [kind](https://kind.sigs.k8s.io/) cluster — with one command. No cloud
> accounts, DNS, or browser required.

## Next steps

- [Multi-issuer authentication](./multi-issuer.md) — the headline feature.
- [Configuration reference](./configuration.md) — all flags, impersonation, and
  task recipes.
- [Architecture](./architecture.md) — how the proxy works.
- [Operations](./operations.md) — security, troubleshooting, and local testing.
- [Chart values reference](../chart/kube-oidc-proxy/README.md).
