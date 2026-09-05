# Getting started

One complete first installation: decide how the proxy will authenticate,
install the chart, expose it, give one identity a role, and verify an allowed
and a denied request. At the end you have a proxy that a person or a pipeline
can use, and a way to check that every later change still works.

The chart in [`../chart/kube-oidc-proxy`](../chart/kube-oidc-proxy) creates the
Deployment, Service, ServiceAccount and the impersonation RBAC the proxy needs,
in a `kube-oidc-proxy` namespace. The
[chart README](../chart/kube-oidc-proxy/README.md) is the full values
reference.

- [Prerequisites](#prerequisites)
- [1. Decide how it will authenticate](#1-decide-how-it-will-authenticate)
- [2. Install](#2-install)
  - [From the OCI registry (recommended)](#from-the-oci-registry-recommended)
  - [From a local checkout](#from-a-local-checkout)
  - [As raw manifests](#as-raw-manifests)
- [3. Expose it](#3-expose-it)
- [4. Serving TLS](#4-serving-tls)
- [5. Give one identity a role](#5-give-one-identity-a-role)
- [Verify the first identity](#verify-the-first-identity)
- [Point kubectl at the proxy](#point-kubectl-at-the-proxy)
- [Next steps](#next-steps)


## Prerequisites

- A Kubernetes cluster and `kubectl`. The end-to-end suite runs against the
  current Kubernetes minor and the two before it; the exact versions are
  declared in
  [`test/e2e/versions/kubernetes-versions.json`](../test/e2e/versions/kubernetes-versions.json).
  Multi-issuer configuration uses the `AuthenticationConfiguration` format
  that kube-apiserver itself consumes, so it needs no particular API server
  version: the proxy does the parsing.
- [Helm](https://helm.sh) 3+ (developed and tested against Helm v4).
- An identity provider that publishes an OIDC discovery document and a JWKS
  (the `.well-known/openid-configuration` URL and the signing keys it points
  to). GitHub Actions, GitLab, Google, Dex, Keycloak and TeamCity all do.
- A way to obtain a token from it during setup: a CI job that requests one, a
  browser login, or the provider's own token endpoint. The verification steps
  below need one.
- Optional: [cert-manager](https://github.com/jetstack/cert-manager), to issue
  the proxy's serving certificate.

Two things the proxy changes that are worth knowing before installing. Its
ServiceAccount is allowed to impersonate any user, group and extra against the
API server, so treat the Deployment and its RBAC as privileged. And clients
will talk to the proxy instead of the API server, so they need a kubeconfig
that points at it; the API server's own endpoint keeps working unchanged for
everyone else.

> [!TIP]
> No identity provider yet? The [multi-issuer demo](../demo/README.md) stands
> up two Dex issuers and the proxy in a local [kind](https://kind.sigs.k8s.io/)
> cluster with one command, no cloud accounts, DNS or browser required.

## 1. Decide how it will authenticate

The proxy authenticates one of two ways, and the choice shapes the values
file. Read [choosing a configuration](./authentication.md#choosing-a-configuration)
once; the short version:

| You have | Use | Values |
| --- | --- | --- |
| One issuer and simple needs: username from a claim, optionally groups and a prefix | the `--oidc-*` flags | `oidc.clientId`, `oidc.issuerUrl`, `oidc.usernameClaim`, … |
| One or more issuers, or any need for CEL: synthesized groups, `extra` for audit, numeric-ID pinning | an `AuthenticationConfiguration` | `authenticationConfig.content` |

For a CI system such as GitHub Actions, the second form is the one to use
even with a single issuer, because its tokens carry no groups claim and the
recipe synthesizes them. This guide uses that form; the flag form is a
three-line values change shown under
[single-issuer with flags](./authentication.md#single-issuer-with-flags).

Take the issuer entry for your provider from [integrations](./integrations.md)
and put it in a values file. Every example there is redacted; the values to
replace are the audience, the organisation or project names, and the numeric
IDs the validation rules pin.

```yaml
# values.yaml
authenticationConfig:
  content: |
    apiVersion: apiserver.config.k8s.io/v1
    kind: AuthenticationConfiguration
    jwt:
    - issuer:
        url: https://token.actions.githubusercontent.com
        audiences: ["kube-oidc-proxy.example.com"]   # the hostname clients will use
      claimMappings:
        username:
          expression: '"gha:" + claims.repository + ":" + claims.ref'
        groups:
          expression: '["gha:org:" + claims.repository_owner, "gha:repo:" + claims.repository]'
      claimValidationRules:
      - expression: 'claims.repository_owner_id == "1234567"'
        message: "token not issued for the expected organisation"
```

The audience deserves a moment: it is the string the token's `aud` must equal,
and the natural choice is the hostname the proxy will be reached at, so a
token minted for one proxy cannot be replayed against another.

## 2. Install

### From the OCI registry (recommended)

```sh
helm install kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  --namespace kube-oidc-proxy --create-namespace -f values.yaml
```

The chart and image are signed (cosign, keyless). Add `--version <x.y.z>` to pin
a specific [release](https://github.com/rafpe/kube-oidc-proxy/releases); omit it
for the latest. Later upgrades use the same command with `upgrade` in place of
`install`; keep passing `-f values.yaml` rather than `--reuse-values`, which
would not pick up defaults added by a newer chart.

### From a local checkout

```sh
helm install kube-oidc-proxy ./chart/kube-oidc-proxy \
  --namespace kube-oidc-proxy --create-namespace -f values.yaml
```

### As raw manifests

Prefer plain YAML for `kubectl apply` or GitOps? Render it from the chart:

```sh
helm template kube-oidc-proxy ./chart/kube-oidc-proxy \
  --namespace kube-oidc-proxy -f values.yaml > kube-oidc-proxy.yaml
kubectl apply -f kube-oidc-proxy.yaml
```

Wait for the pod to report ready. In multi-issuer configuration that means at
least one issuer's JWKS has loaded; the log says which:

```sh
kubectl -n kube-oidc-proxy rollout status deploy/kube-oidc-proxy
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy \
  | jq -r 'select(.event_type == "oidc.issuer.initialized") | .issuer_name'
```

## 3. Expose it

The chart creates a `ClusterIP` Service, so out of the box the proxy is
reachable only inside the cluster. Clients outside it need one of two things
in front.

**Behind an ingress that terminates TLS.** The usual choice on a managed
cluster. Two details matter: the proxy has no plaintext listener, so the
ingress must re-encrypt to the pod, and `kubectl` holds connections open for
`watch`, `logs -f` and `exec`, so the ingress must not cut idle streams at its
default timeout. With ingress-nginx:

```yaml
ingress:
  enabled: true
  ingressClassName: nginx
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
  hosts:
    - host: kube-oidc-proxy.example.com
      paths:
        - /
  tls:
    - secretName: kube-oidc-proxy-ingress-tls   # a certificate for that hostname
      hosts:
        - kube-oidc-proxy.example.com
```

The ingress certificate is the one clients see, so it must cover the hostname;
a certificate for a different name, or the controller's default one, is the
most common first failure. The pod's own serving certificate is only used on
the hop from the ingress to the pod; the chart's self-signed default is fine
there, since ingress controllers do not verify upstream certificates unless
told to.

**With a LoadBalancer Service.** The proxy terminates TLS itself, so the
serving certificate below is the one clients see:

```yaml
service:
  type: LoadBalancer
  annotations: {}      # your cloud's load balancer hints
```

Whichever you choose, confirm the hostname resolves to the entrypoint and
that a request reaches the proxy rather than something in front of it:

```sh
curl -sk -o /dev/null -D - https://kube-oidc-proxy.example.com/ | grep -i -E "^HTTP|^server"
```

A 401 from the proxy is the right answer here: it received the request and
found no token. A 404 with a load balancer's or ingress controller's own
`Server` header means the request never reached it.

## 4. Serving TLS

The proxy terminates TLS for whoever connects to the pod, the ingress or the
clients themselves. Provide its serving certificate one of three ways.

**Self-signed (default).** With no TLS values set, the chart generates a
self-signed certificate. Fine behind an ingress; for direct clients they must
trust the generated CA.

**cert-manager.** Let [cert-manager](https://github.com/jetstack/cert-manager)
issue it. The chart's Certificate covers the in-cluster Service name; for a
public hostname, issue a certificate for that name yourself and reference the
Secret as below.

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

## 5. Give one identity a role

The proxy decides who a request is; the API server decides what they may do,
from RBAC bindings on the username and groups the mapping produced. Nothing
is allowed until you bind something. A read-only role on the repo-level
group from the example above:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-readers
subjects:
- kind: Group
  name: "gha:repo:my-org/my-repo"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
```

The group is bound by its exact string, prefix and all. The
[integrations](./integrations.md) recipes say which groups each mapping
produces and which tier to bind for what.

## Verify the first identity

Obtain a token from the identity provider for the audience you configured,
then ask the cluster who it is:

```sh
kubectl --server=https://kube-oidc-proxy.example.com --token="$TOKEN" auth whoami
```

```text
ATTRIBUTE   VALUE
Username    gha:my-org/my-repo:refs/heads/main
Groups      [gha:org:my-org gha:repo:my-org/my-repo system:authenticated]
```

That output is the mapped identity exactly as the API server saw it, with the
`system:authenticated` group the API server adds itself. Then prove
authorization is scoped, with one allowed and one denied action:

```sh
kubectl --server=https://kube-oidc-proxy.example.com --token="$TOKEN" get namespaces   # allowed by view
kubectl --server=https://kube-oidc-proxy.example.com --token="$TOKEN" get secrets -A   # forbidden: view excludes secrets
kubectl --server=https://kube-oidc-proxy.example.com --token="$TOKEN" auth can-i create deployments -n default   # no
```

If `auth whoami` fails, the [first checks](./operations.md#first-checks) in
operations separate the four places it can fail: the path in front of the
proxy, the token, the proxy's own RBAC, and the identity's RBAC. To take the
network out of the picture entirely, port-forward straight to the Service:

```sh
kubectl -n kube-oidc-proxy port-forward svc/kube-oidc-proxy 8443:443 &
kubectl --server=https://127.0.0.1:8443 --insecure-skip-tls-verify=true --token="$TOKEN" auth whoami
```

## Point kubectl at the proxy

Hand users a kubeconfig that talks to the proxy instead of the API server. For
a pipeline or a script that already mints tokens, the cluster entry is all
that changes, and the token is passed on the command line or in the user
entry:

```yaml
apiVersion: v1
kind: Config
clusters:
  - cluster:
      server: https://kube-oidc-proxy.example.com
      # certificate-authority: /path/to/ca.pem   # only if the serving certificate is not publicly trusted
    name: my-cluster
users:
  - name: ci
    user:
      token: <id-token>
contexts:
  - context:
      cluster: my-cluster
      user: ci
    name: my-cluster
current-context: my-cluster
```

For people logging in interactively, use
[kubelogin](https://github.com/int128/kubelogin) (`kubectl oidc-login`), a
credential plugin that runs the OIDC flow in the browser, then caches and
refreshes the ID token automatically:

```sh
kubectl krew install oidc-login   # or: brew install kubelogin
```

```yaml
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

## Next steps

- [Integrations](./integrations.md) — the full recipe for your provider, with
  trust tiers and audit extras.
- [Authentication and identity](./authentication.md) — the impersonation
  model, `kubectl --as`, passthrough, glossary and common questions.
- [Operations](./operations.md) — first checks, troubleshooting, watching
  requests, upgrades and outages.
- [Auditing](./auditing.md) — the audit trail on the proxy and the API server.
- [Chart values reference](../chart/kube-oidc-proxy/README.md).
