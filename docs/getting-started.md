# Getting started

Deploy `kube-oidc-proxy` with the Helm chart, configure an authentication mode,
and point `kubectl` at it. The chart in
[`../chart/kube-oidc-proxy`](../chart/kube-oidc-proxy) creates the Deployment,
Service, ServiceAccount, and impersonation RBAC in a `kube-oidc-proxy`
namespace. The [chart README](../chart/kube-oidc-proxy/README.md) is the full
values reference.

## Prerequisites

- A Kubernetes cluster and `kubectl`.
- [Helm](https://helm.sh) 3+ (developed and tested against Helm v4).
- One or more OIDC issuers that publish a discovery document and JWKS.
- Optional: [cert-manager](https://github.com/jetstack/cert-manager), to issue
  the proxy's serving certificate.

> [!IMPORTANT]
> The image `ghcr.io/rafpe/kube-oidc-proxy:1.1.0` is **published** — the local
> chart (option 1) pulls it and works today. The OCI chart
> `oci://ghcr.io/rafpe/charts/kube-oidc-proxy` is not published yet; use it only
> once the release pipeline lands.

## Install

### 1. From a local checkout

```sh
helm install kube-oidc-proxy ./chart/kube-oidc-proxy \
  --namespace kube-oidc-proxy --create-namespace \
  --set oidc.clientId=<client-id> \
  --set oidc.issuerUrl=https://<issuer-url> \
  --set oidc.usernameClaim=email
```

### 2. From the OCI registry (once published)

```sh
helm install kube-oidc-proxy \
  oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
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
> When `authenticationConfig.content` is set, the chart passes
> `--authentication-config` and **omits every `--oidc-*` flag**; the `oidc.*`
> values are ignored. Setting both fails startup with
> `authentication-config and --oidc-* flags are mutually exclusive`.

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
`kube-oidc-proxy` instead of the API server directly, using the `oidc` auth
provider:

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
      auth-provider:
        name: oidc
        config:
          client-id: <client-id>
          client-secret: <client-secret>
          idp-issuer-url: https://<issuer-url>
          id-token: <id-token>
          refresh-token: <refresh-token>
```

> [!TIP]
> [OpenUnison](https://openunison.github.io/) integrates `kube-oidc-proxy`
> directly and bundles an identity provider and access portal — a fast way to
> get an end-to-end login flow if you don't already have an OIDC IdP.

## Next steps

- [Multi-issuer authentication](./multi-issuer.md) — the headline feature.
- [Configuration reference](./configuration.md) — all flags, impersonation, and
  task recipes.
- [Architecture](./architecture.md) — how the proxy works.
- [Operations](./operations.md) — security, troubleshooting, and local testing.
- [Chart values reference](../chart/kube-oidc-proxy/README.md).
