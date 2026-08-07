# Installation

The recommended way to deploy is the Helm chart in
[`../chart/kube-oidc-proxy`](../chart/kube-oidc-proxy). It creates the
Deployment, Service, ServiceAccount, and impersonation RBAC in a
`kube-oidc-proxy` namespace. See the
[chart README](../chart/kube-oidc-proxy/README.md) for the full values
reference.

## Prerequisites

- A Kubernetes cluster and `kubectl`.
- [Helm](https://helm.sh) 3+ (the chart is developed and tested against Helm v4).
- One or more OIDC issuers that publish a discovery document and JWKS.
- Optionally, [cert-manager](https://github.com/jetstack/cert-manager) if you
  want it to issue the proxy's serving certificate.

> [!IMPORTANT]
> The container image `ghcr.io/rafpe/kube-oidc-proxy:1.1.0` and the OCI chart
> `oci://ghcr.io/rafpe/charts/kube-oidc-proxy` are the **intended** published
> artifacts. The release pipeline is still pending, so they may not be pushed
> yet — until then, install from a local checkout (option 2).

## Deployment options

### 1. Install from the OCI registry

```sh
helm install kube-oidc-proxy \
  oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  --namespace kube-oidc-proxy --create-namespace \
  --set oidc.clientId=<client-id> \           # 👈 your OIDC client ID
  --set oidc.issuerUrl=https://<issuer-url> \  # 👈 your OIDC issuer
  --set oidc.usernameClaim=email               # 👈 claim used as the username
```

### 2. Install from a local checkout

```sh
helm install kube-oidc-proxy ./chart/kube-oidc-proxy \
  --namespace kube-oidc-proxy --create-namespace \
  --set oidc.clientId=<client-id> \
  --set oidc.issuerUrl=https://<issuer-url> \
  --set oidc.usernameClaim=email
```

### 3. Render raw manifests

Prefer plain YAML for `kubectl apply` or GitOps? Render it from the chart
instead of maintaining a separate copy:

```sh
helm template kube-oidc-proxy ./chart/kube-oidc-proxy \
  --namespace kube-oidc-proxy -f my-values.yaml > kube-oidc-proxy.yaml
kubectl apply -f kube-oidc-proxy.yaml
```

## Serving TLS

The proxy terminates TLS for its clients. Choose one of three ways to provide
its serving certificate.

### Self-signed (default)

With no TLS values set, the chart generates a self-signed serving certificate.
Good for a quick start; clients must trust the generated CA.

### cert-manager

Let [cert-manager](https://github.com/jetstack/cert-manager) issue the
certificate:

```yaml
tls:
  certManager: true
  selfSigned: true          # create a self-signed Issuer
  # selfSigned: false
  # issuerName: my-issuer   # ...or reference your own Issuer
```

### Your own Secret

Reference an existing `kubernetes.io/tls` Secret that holds the key and cert:

```yaml
tls:
  secretName: my-tls-secret-with-key-and-cert
```

## Build the kubeconfig

Once the proxy Service has an address, hand users a kubeconfig that talks to
`kube-oidc-proxy` instead of the API server directly, using the `oidc` auth
provider:

```yaml
apiVersion: v1
clusters:
  - cluster:
      certificate-authority: /path/to/proxy-ca.pem  # 👈 the proxy's serving CA
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
> get an end-to-end login flow if you don't already have an OIDC IdP wired up.

## See also

- [Usage: configuring authentication](./usage.md)
- [Chart values reference](../chart/kube-oidc-proxy/README.md)
- [Troubleshooting](./troubleshooting.md)
