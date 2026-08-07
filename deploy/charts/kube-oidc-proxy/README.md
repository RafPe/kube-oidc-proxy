# kube-oidc-proxy Helm chart

Helm chart for [`kube-oidc-proxy`](https://github.com/rafpe/kube-oidc-proxy) — a
reverse proxy that authenticates requests with OpenID Connect (OIDC) and
impersonates the authenticated user against the Kubernetes API server.

The chart supports the proxy's two **mutually exclusive** authentication modes:

- **Single-issuer** — the classic `--oidc-*` flags. Set `oidc.clientId`,
  `oidc.issuerUrl` and `oidc.usernameClaim`.
- **Multi-issuer** — a Kubernetes `AuthenticationConfiguration`. Set
  `authenticationConfig.content` (and optionally `readinessRequireAllIssuers`).

When `authenticationConfig.content` is non-empty the chart passes
`--authentication-config` and **omits every `--oidc-*` flag**; the `oidc.*`
values are ignored. Do not configure both modes at once.

## Prerequisites

- Kubernetes cluster and `kubectl`
- Helm 3+ (developed and tested against Helm v4)
- Optionally [cert-manager](https://github.com/jetstack/cert-manager) if you want
  it to issue the proxy's serving certificate

## Install

The chart is not published to a registry; install it from a checkout of this
repository.

Single-issuer:

```sh
helm install kube-oidc-proxy ./deploy/charts/kube-oidc-proxy \
  --set oidc.clientId=my-client \
  --set oidc.issuerUrl=https://accounts.google.com \
  --set oidc.usernameClaim=email
```

Or with a values file:

```sh
helm install kube-oidc-proxy ./deploy/charts/kube-oidc-proxy -f my-values.yaml
```

Uninstall:

```sh
helm uninstall kube-oidc-proxy
```

## Values

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `replicaCount` | int | `1` | Number of proxy replicas. |
| `image.repository` | string | `ghcr.io/rafpe/kube-oidc-proxy` | Container image repository. |
| `image.tag` | string | `"1.1.0"` | Image tag (pin an explicit version; never `latest`). |
| `image.pullPolicy` | string | `IfNotPresent` | Image pull policy. |
| `imagePullSecrets` | list | `[]` | Secrets for pulling from a private registry. |
| `nameOverride` | string | `""` | Override the chart-name portion of resource names. |
| `fullnameOverride` | string | `""` | Override the full release name. |
| `service.type` | string | `ClusterIP` | Service type. |
| `service.port` | int | `443` | Service port (forwarded to container port 8443). |
| `service.loadBalancerIP` | string | `""` | Static IP for a LoadBalancer Service. |
| `service.loadBalancerSourceRanges` | list | `[]` | Allowed source CIDRs for a LoadBalancer Service. |
| `tls.secretName` | string | `nil` | Name of an existing `kubernetes.io/tls` Secret. If unset, a self-signed cert is generated. |
| `tls.certManager` | bool | `false` | Let cert-manager issue the serving certificate. |
| `tls.selfSigned` | bool | `true` | With cert-manager, create a self-signed Issuer. |
| `tls.issuerName` | string | `nil` | Existing cert-manager Issuer to reference when `selfSigned` is false. |
| `oidc.clientId` | string | `""` | **Single-issuer**: OIDC client ID. Ignored in multi-issuer mode. |
| `oidc.issuerUrl` | string | `""` | **Single-issuer**: OIDC issuer URL. Ignored in multi-issuer mode. |
| `oidc.usernameClaim` | string | `""` | **Single-issuer**: token claim used as username. Ignored in multi-issuer mode. |
| `oidc.caPEM` | string | `nil` | PEM CA that verifies the issuer TLS connection. Ignored in multi-issuer mode. |
| `oidc.usernamePrefix` | string | `nil` | Prefix prepended to usernames. |
| `oidc.groupsClaim` | string | `nil` | Token claim carrying groups. |
| `oidc.groupsPrefix` | string | `nil` | Prefix prepended to group names. |
| `oidc.signingAlgs` | list | `[RS256]` | Accepted JWT signing algorithms. |
| `oidc.requiredClaims` | map | `{}` | Claims that must equal a value. Each entry becomes a repeatable `--oidc-required-claim=k=v` flag. |
| `authenticationConfig.content` | string | `""` | **Multi-issuer**: YAML of an `AuthenticationConfiguration`. When set, `--authentication-config` is used and all `--oidc-*` flags are omitted. |
| `readinessRequireAllIssuers` | bool | `false` | **Multi-issuer**: require every issuer to initialize before the pod is ready. |
| `tokenPassthrough.enabled` | bool | `false` | Forward non-OIDC bearer tokens to the API server. |
| `tokenPassthrough.audiences` | list | `[]` | Allowed audiences for passthrough tokens. |
| `extraImpersonationHeaders.clientIP` | bool | `false` | Send client source IP as an extra user header. |
| `extraArgs` | map | `{}` | Extra CLI flags passed as `--key=value`. |
| `extraVolumeMounts` | list | `{}` | Extra container volumeMounts. |
| `extraVolumes` | list | `{}` | Extra pod volumes. |
| `ingress.enabled` | bool | `false` | Create an Ingress. |
| `ingress.annotations` | map | `{}` | Ingress annotations. |
| `ingress.hosts` | list | see values | Ingress hosts and paths. |
| `ingress.tls` | list | `[]` | Ingress TLS blocks. |
| `podDisruptionBudget.enabled` | bool | `false` | Create a PodDisruptionBudget. |
| `podDisruptionBudget.minAvailable` | int | `1` | Minimum available pods. |
| `resources` | map | `{}` | Container resource requests/limits. |
| `initContainers` | list | `[]` | Init containers. |
| `nodeSelector` | map | `{}` | Node selector. |
| `tolerations` | list | `[]` | Tolerations. |
| `affinity` | map | `{}` | Affinity rules. |

## Single-issuer example

```yaml
oidc:
  clientId: my-client
  issuerUrl: https://accounts.google.com
  usernameClaim: email
  groupsClaim: groups
  requiredClaims:
    hd: example.com
```

If the issuer presents a certificate from a private CA, supply it inline:

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

## Multi-issuer example

Accept tokens from several identity providers by supplying a Kubernetes
`AuthenticationConfiguration`. Each issuer's CA (if any) must be inline under
`issuer.certificateAuthority`.

```yaml
# All oidc.* fields are ignored while this is set.
readinessRequireAllIssuers: false
authenticationConfig:
  content: |
    apiVersion: apiserver.config.k8s.io/v1beta1
    kind: AuthenticationConfiguration
    jwt:
      - issuer:
          url: https://accounts.google.com
          audiences:
            - my-google-client
        claimMappings:
          username:
            claim: email
            prefix: "google:"
      - issuer:
          url: https://token.actions.githubusercontent.com
          audiences:
            - my-github-client
        claimMappings:
          username:
            claim: sub
            prefix: "github:"
```

With `readinessRequireAllIssuers: false` (the default) the pod becomes ready as
soon as at least one issuer initializes, so a single IdP outage cannot block a
rollout for every other system. Set it to `true` to require all issuers.

## TLS

By default the chart generates a self-signed serving certificate. To provide
your own, create a `kubernetes.io/tls` Secret and reference it:

```yaml
tls:
  secretName: my-tls-secret-with-key-and-cert
```

Or have cert-manager issue it:

```yaml
tls:
  certManager: true
  selfSigned: true   # or false + issuerName: my-issuer
```

## Ingress

```yaml
ingress:
  enabled: true
  annotations:
    kubernetes.io/ingress.class: traefik
  hosts:
    - host: oidc-proxy.example.com
      paths:
        - /
```

## Testing the chart

Committed fixtures under `ci/` cover both modes and are used by the
`helm-chart` GitHub Actions workflow:

```sh
helm lint deploy/charts/kube-oidc-proxy -f deploy/charts/kube-oidc-proxy/ci/single-issuer-values.yaml
helm template t deploy/charts/kube-oidc-proxy -f deploy/charts/kube-oidc-proxy/ci/multi-issuer-values.yaml
```
