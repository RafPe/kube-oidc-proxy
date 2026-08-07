# kube-oidc-proxy

`kube-oidc-proxy` is a reverse proxy server to authenticate users using OIDC to
Kubernetes API servers where OIDC authentication is not available (i.e. managed 
Kubernetes providers such as GKE, EKS, etc).

This intermediary server takes `kubectl` requests, authenticates the request using
the configured OIDC Kubernetes authenticator, then attaches impersonation
headers based on the OIDC response from the configured provider. This
impersonated request is then sent to the API server on behalf of the user and
it's response passed back. The server has flag parity with secure serving and
OIDC authentication that are available with the Kubernetes API server as well as
client flags provided by kubectl. In-cluster client authentication is also
available when running `kube-oidc-proxy` as a pod.

Since the proxy server utilises impersonation to forward requests to the API
server once authenticated, impersonation is disabled for user requests to the
API server.

![kube-oidc-proxy demo](https://storage.googleapis.com/kube-oidc-proxy/demo-9de755f8e4b4e5dd67d17addf09759860f903098.svg)

The following is a diagram of the request flow for a user request.
![kube-oidc-proxy request
flow](https://storage.googleapis.com/kube-oidc-proxy/diagram-d9623e38a6cd3b585b45f47d80ca1e1c43c7e695.png)

## Quickest Start

OpenUnison integrates kube-oidc-proxy directly, and includes an identity provider and access portal for Kubernetes.  The quickest way to get started with kube-oidc-proxy is to follow the directions for OpenUnison's deployment at https://openunison.github.io/.

## Tutorial

Directions on how to deploy OIDC authentication with multi-cluster can be found
[here.](./demo/README.md) or there is a [helm chart](./deploy/charts/kube-oidc-proxy/README.md).

### Quickstart

Install with the [Helm chart](./deploy/charts/kube-oidc-proxy/README.md). This
creates the Deployment, Service, ServiceAccount and RBAC in a
`kube-oidc-proxy` Namespace:

```
helm upgrade --install kube-oidc-proxy ./deploy/charts/kube-oidc-proxy \
  --namespace kube-oidc-proxy --create-namespace \
  --set oidc.clientId=<client-id> \
  --set oidc.issuerUrl=https://<issuer-url> \
  --set oidc.usernameClaim=email
```

See the [chart README](./deploy/charts/kube-oidc-proxy/README.md) for all values —
including multi-issuer auth (`authenticationConfig.content`), serving TLS
(cert-manager or chart-generated), and HA settings (PDB, topology spread,
anti-affinity).

Prefer raw manifests for `kubectl apply`? Render them from the chart instead of
maintaining separate YAML:

```
helm template kube-oidc-proxy ./deploy/charts/kube-oidc-proxy \
  --namespace kube-oidc-proxy -f my-values.yaml > kube-oidc-proxy.yaml
kubectl apply -f kube-oidc-proxy.yaml
```

Once the proxy Service has an address, create a Kubeconfig to point to
`kube-oidc-proxy` and set up your OIDC authenticated Kubernetes user.

```
apiVersion: v1
clusters:
- cluster:
    certificate-authority: *
    server: https://[url|ip:443]
  name: *
contexts:
- context:
    cluster: *
    user: *
  name: *
kind: Config
preferences: {}
users:
- name: *
  user:
    auth-provider:
      config:
        client-id: *
        client-secret: *
        id-token: *
        idp-issuer-url: *
        refresh-token: *
      name: oidc
```

## Configuration
 - [Multi-issuer OIDC authentication](./docs/tasks/multi-issuer.md)
 - [Token Passthrough](./docs/tasks/token-passthrough.md)
 - [No Impersonation](./docs/tasks/no-impersonation.md)
 - [Extra Impersonations Headers](./docs/tasks/extra-impersonation-headers.md)
 - [Auditing](./docs/tasks/auditing.md)

## Logging

In addition to auditing, kube-oidc-proxy logs all requests to standard out so the requests can be captured by a common Security Information and Event Management (SIEM) system.  SIEMs will typically import logs directly from containers via tools like fluentd.  This logging is also useful in debugging.  An example successful event:

```
[2021-11-25T01:05:17+0000] AuSuccess src:[10.42.0.5 / 10.42.1.3, 10.42.0.5] URI:/api/v1/namespaces/openunison/pods?limit=500 inbound:[mlbadmin1 / system:masters|system:authenticated /]
```

The first block, between `[]` is an ISO-8601 timestamp.  The next text, `AuSuccess`, indicates that authentication was successful.  the `src` block containers the remote address of the request, followed by the value of the `X-Forwarded-For` HTTP header if provided.  The `URI` is the URL path of the request.  The `inbound` section provides the user name, groups, and extra-info provided to the proxy from the JWT.

When there's an error or failure:

```
[2021-11-25T01:05:24+0000] AuFail src:[10.42.0.5 / 10.42.1.3] URI:/api/v1/nodes
```

This is similar to success, but without the token information.

## End-User Impersonation

kube-oidc-proxy supports the impersonation headers for inbound requests.  This allowes the proxy to support `kubectl --as`.  When impersonation headers are included in a request, the proxy checks that the authenticated user is able to assume the identity of the impersonation headers by submitting `SubjectAccessReview` requests to the API server.  Once authorized, the proxy will send those identity headers instead of headers generated for the authenticated user.  In addition, three `Extra` impersonation headers are sent to the API server to identify the authenticated user who's making the request:

| Header | Description |
| ------ | ----------- |
| `originaluser.jetstack.io-user` | The original username |
| `originaluser.jetstack.io-groups` | The original groups |
| `originaluser.jetstack.io-extra` | A JSON encoded map of arrays representing all of the `extra` headers included in the original identity |

In addition to sending this `extra` information, the proxy adds an additional section to the logfile that will identify outbound identity data.  When impersonation headers are present, the `AuSuccess` log will look like:

```
[2021-11-25T01:05:17+0000] AuSuccess src:[10.42.0.5 / 10.42.1.3] URI:/api/v1/namespaces/openunison/pods?limit=500 inbound:[mlbadmin1 / system:masters|system:authenticated /] outbound:[mlbadmin2 / group2|system:authenticated /]
```

When using `Impersonate-Extra-` headers, the proxy's `ServiceAccount` must be explicitly authorized via RBAC to impersonate whatever the extra key is named.  This is because extras are treated as subresources which must be explicitly authorized.  


## Development
*NOTE*: building kube-oidc-proxy requires Go version 1.17 or higher.

To help with development, there is a suite of tools you can use to deploy a
functioning proxy from source locally. You can read more
[here](./docs/tasks/development-testing.md).

### End-to-end tests

`make e2e` runs the Go end-to-end suite (`test/e2e/suite`) against a real
Kubernetes cluster. It is hermetic: it builds the proxy and the test-tool
images from source, creates its own [kind](https://kind.sigs.k8s.io) cluster,
loads the images, runs the suite, and tears the cluster down again on exit
(including on failure or interrupt). No pre-existing cluster is required.

Prerequisites (all on `PATH`): `go`, `docker` (daemon running), `kind`,
`kubectl`. Images are built for the host architecture so the suite runs on both
`amd64` and `arm64` (e.g. Apple Silicon).

```sh
make e2e          # build images, spin up kind, run the suite, tear down
make e2e-clean    # delete a leftover e2e kind cluster (safe if none exists)
```

Useful overrides: `E2E_TIMEOUT` (Go test timeout, default `30m`) and
`KUBE_OIDC_PROXY_K8S_VERSION` (kind node image version).

The suite runs in CI on every pull request and on pushes to `main`
(`.github/workflows/e2e.yaml`). A companion workflow
(`.github/workflows/e2e-oidc-gha.yaml`) additionally proves the multi-issuer
union authenticator against the **real** GitHub Actions OIDC issuer alongside a
local Dex issuer.
