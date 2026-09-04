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
`--authentication-config` and omits issuer-specific `--oidc-*` flags.
`oidc.tlsClient` remains available because its credentials apply to every
issuer in either mode.

## Prerequisites

- Kubernetes cluster and `kubectl`
- Helm 3+ (developed and tested against Helm v4)
- Optionally [cert-manager](https://github.com/jetstack/cert-manager) if you want
  it to issue the proxy's serving certificate

## Install

The chart is published as a signed OCI artifact at
`oci://ghcr.io/rafpe/charts/kube-oidc-proxy`. Add `--version <x.y.z>` to pin a
specific release (see [releases](https://github.com/rafpe/kube-oidc-proxy/releases));
omit it for the latest. To work from a local checkout instead, replace the chart
reference with `./chart/kube-oidc-proxy`.

Single-issuer:

```sh
helm install kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  --set oidc.clientId=my-client \
  --set oidc.issuerUrl=https://accounts.google.com \
  --set oidc.usernameClaim=email
```

Or with a values file:

```sh
helm install kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy -f my-values.yaml
```

Uninstall:

```sh
helm uninstall kube-oidc-proxy
```

## Values

Every value in [`values.yaml`](./values.yaml).

### Image & naming

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `replicaCount` | int | `1` | Number of proxy replicas. |
| `image.repository` | string | `ghcr.io/rafpe/kube-oidc-proxy` | Container image repository. |
| `image.tag` | string | `""` | Image tag. Empty uses the chart `appVersion`, which matches the chart version on every release. Set to pin a different explicit version; never `latest`. |
| `image.pullPolicy` | string | `IfNotPresent` | Image pull policy. |
| `imagePullSecrets` | list | `[]` | Secrets for pulling from a private registry. |
| `nameOverride` | string | `""` | Override the chart-name portion of resource names. |
| `fullnameOverride` | string | `""` | Override the full release name. |

### Service

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `service.type` | string | `ClusterIP` | Service type (`ClusterIP`, `NodePort`, `LoadBalancer`). |
| `service.port` | int | `443` | Service port (forwarded to container port 8443). |
| `service.annotations` | map | `{}` | Annotations added to the Service (e.g. cloud LB hints). |
| `service.loadBalancerIP` | string | `""` | Static IP for a LoadBalancer Service. |
| `service.loadBalancerSourceRanges` | list | `[]` | Allowed source CIDRs for a LoadBalancer Service. |
| `service.internalTrafficPolicy` | string | `""` | Routing of in-cluster traffic: `Cluster` or `Local`. Empty = cluster default. |
| `service.externalTrafficPolicy` | string | `""` | Routing of external traffic (NodePort/LoadBalancer): `Cluster` or `Local` (preserves client source IP). Ignored for ClusterIP. |
| `service.trafficDistribution` | string | `""` | Topology-aware routing (K8s 1.31+): `PreferClose` to prefer same-zone endpoints. Empty = disabled. |
| `service.sessionAffinity` | string | `""` | Session stickiness: `ClientIP` or `None`. Empty = default. |

### TLS (proxy serving certificate)

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `tls.secretName` | string | `nil` | Name of an existing `kubernetes.io/tls` Secret. If unset, a self-signed cert is generated. |
| `tls.certManager` | bool | `false` | Let cert-manager issue the serving certificate. |
| `tls.selfSigned` | bool | `true` | With cert-manager, create a self-signed Issuer. |
| `tls.issuerName` | string | `nil` | Existing cert-manager Issuer to reference when `selfSigned` is false. |

### Authentication — single-issuer

Ignored when `authenticationConfig.content` is set.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `oidc.clientId` | string | `""` | OIDC client ID expected in the token audience. |
| `oidc.issuerUrl` | string | `""` | OIDC issuer URL (must serve a discovery document). |
| `oidc.usernameClaim` | string | `""` | Token claim used as the username. |
| `oidc.caPEM` | string | `nil` | PEM CA that verifies the issuer TLS connection. |
| `oidc.usernamePrefix` | string | `nil` | Prefix prepended to usernames. |
| `oidc.groupsClaim` | string | `nil` | Token claim carrying groups. |
| `oidc.groupsPrefix` | string | `nil` | Prefix prepended to group names. |
| `oidc.signingAlgs` | list | `[RS256]` | Accepted JWT signing algorithms. |
| `oidc.requiredClaims` | map | `{}` | Claims that must equal a value. Each entry becomes a repeatable `--oidc-required-claim=k=v` flag. |

### Authentication — multi-issuer

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `authenticationConfig.content` | string | `""` | YAML of an `AuthenticationConfiguration`. When set, `--authentication-config` is used and issuer-specific `--oidc-*` flags are omitted. |
| `oidc.tlsClient.existingSecret` | string | `""` | Existing Secret containing the client certificate/key used for mTLS to every configured OIDC issuer. |
| `oidc.tlsClient.certKey` | string | `"tls.crt"` | Certificate key in `oidc.tlsClient.existingSecret`. |
| `oidc.tlsClient.keyKey` | string | `"tls.key"` | Private-key key in `oidc.tlsClient.existingSecret`. |
| `readinessRequireAllIssuers` | bool | `false` | Require every issuer to initialize before the pod is ready. Default: ready once at least one initializes. |

### Token passthrough & impersonation

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `tokenPassthrough.enabled` | bool | `false` | Forward non-OIDC bearer tokens to the API server (validated via TokenReview). |
| `tokenPassthrough.audiences` | list | `[]` | Allowed audiences for passthrough tokens. |
| `tokenPassthrough.cacheSuccessTTL` | string | `""` | How long a successful TokenReview result is cached (`--token-passthrough-cache-success-ttl`). Empty uses the binary default (10s); `"0"` disables. A revoked token keeps passing for up to this long. |
| `tokenPassthrough.cacheFailureTTL` | string | `""` | How long an unauthenticated TokenReview result is cached (`--token-passthrough-cache-failure-ttl`). Empty uses the binary default (10s); `"0"` disables. A newly valid token can be rejected for up to this long. |
| `subjectAccessReview.cacheAllowTTL` | string | `""` (binary default `10s`) | How long an **allowed** impersonation SubjectAccessReview decision is cached (`--subject-access-review-cache-allow-ttl`), as a Go duration. Empty omits the flag. Revoking an impersonation grant can take up to this long to be enforced; `"0"` disables caching of allows. |
| `subjectAccessReview.cacheDenyTTL` | string | `""` (binary default `10s`) | How long a **denied** impersonation SubjectAccessReview decision is cached (`--subject-access-review-cache-deny-ttl`), as a Go duration. Empty omits the flag. A new impersonation grant can take up to this long to be honoured; `"0"` disables caching of denies. |
| `maxImpersonationHeaderValues` | int | `nil` (binary default 64) | Cap on inbound impersonation header values per request (`kubectl --as`: user + every group, uid and extra value); over-cap requests get HTTP 431 before any `SubjectAccessReview`. Sets `--max-impersonation-header-values` when non-empty. |
| `extraImpersonationHeaders.clientIP` | bool | `false` | Send the client source IP as an extra user header. |
| `extraImpersonationHeaders.headers` | string | `nil` | Extra `key=value` user headers (`--extra-user-headers`), comma-separated. |

### Logging

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `logging.format` | string | `json` | Log output format (`--logging-format`): `json` or `text`. |
| `logging.verbosity` | int | `0` | Log verbosity (`--v`). `0` shows lifecycle, access records and warnings; `1` and above add request internals. Rendered before `extraArgs`, so an `extraArgs` entry of the same flag still wins. |

### Extra args, volumes & ingress

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `extraArgs` | map | `{}` | Extra CLI flags passed as `--key=value`. |
| `extraVolumeMounts` | list | `{}` | Extra container volumeMounts. |
| `extraVolumes` | list | `{}` | Extra pod volumes. |
| `ingress.enabled` | bool | `false` | Create an Ingress. |
| `ingress.annotations` | map | `{}` | Ingress annotations. |
| `ingress.ingressClassName` | string | `nil` | IngressClass name for the Ingress. |
| `ingress.hosts` | list | see values | Ingress hosts and paths. |
| `ingress.tls` | list | `[]` | Ingress TLS blocks. |

### High availability & scheduling

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `rollingUpdateStrategy` | map | `nil` | Override the Deployment update strategy (commented out by default). |
| `podDisruptionBudget.enabled` | bool | `false` | Create a PodDisruptionBudget (recommended with `replicaCount` > 1). |
| `podDisruptionBudget.minAvailable` | int/string | `1` | Minimum available pods. Ignored if `maxUnavailable` is set. |
| `podDisruptionBudget.maxUnavailable` | int/string | `""` | Maximum unavailable pods. Takes precedence over `minAvailable`. |
| `podDisruptionBudget.unhealthyPodEvictionPolicy` | string | `""` | How the PDB treats not-yet-ready pods (K8s 1.26+): `IfHealthyBudget` or `AlwaysAllow`. |
| `resources` | map | `{}` | Container resource requests/limits. |
| `initContainers` | list | `[]` | Init containers. |
| `nodeSelector` | map | `{}` | Node selector. |
| `tolerations` | list | `[]` | Tolerations. |
| `affinity` | map | `{}` | Node/pod (anti-)affinity. For HA, spread replicas with soft pod anti-affinity. |
| `topologySpreadConstraints` | list | `[]` | Even placement across zones/nodes (preferred over anti-affinity for balanced spread). |
| `priorityClassName` | string | `""` | Optional PriorityClass for the proxy pod. |
| `podAnnotations` | map | `{}` | Annotations added to the pod template (merged with the chart's config checksum). |

### Security context (hardened by default)

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `podSecurityContext.runAsNonRoot` | bool | `true` | Require the container to run as a non-root user. |
| `podSecurityContext.runAsUser` | int | `1000` | UID to run as (required because the image sets no `USER`). |
| `podSecurityContext.seccompProfile.type` | string | `RuntimeDefault` | Seccomp profile for the pod. |
| `securityContext.allowPrivilegeEscalation` | bool | `false` | Disallow privilege escalation. |
| `securityContext.readOnlyRootFilesystem` | bool | `true` | Mount the root filesystem read-only. Relax if you write locally (e.g. audit log to a file). |
| `securityContext.capabilities.drop` | list | `[ALL]` | Linux capabilities dropped from the container. |

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

## High availability

The chart ships single-replica by default. For production, run more than one
replica and keep them spread and protected during disruptions:

```yaml
replicaCount: 3
podDisruptionBudget:
  enabled: true
  minAvailable: 2
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: kube-oidc-proxy
```

- A `PodDisruptionBudget` keeps voluntary disruptions (node drains) from taking
  the proxy fully offline.
- `topologySpreadConstraints` (preferred) or soft pod `affinity` spread replicas
  across zones/nodes.
- In multi-issuer mode, consider `readinessRequireAllIssuers: false` (the
  default) so a single IdP outage can't block a rollout.

## Security

The chart runs the proxy with a **hardened SecurityContext by default**:
non-root (`runAsUser: 1000`), read-only root filesystem, all Linux capabilities
dropped, no privilege escalation, and the `RuntimeDefault` seccomp profile. The
proxy is a privileged component — its ServiceAccount can impersonate identities
against the API server — so keep those defaults and restrict who can edit the
Deployment and its RBAC. See [`../../docs/operations.md`](../../docs/operations.md#security).

If you enable a feature that writes to the local filesystem (e.g. an
`audit-log-path` to a file), add an `emptyDir` via `extraVolumes` /
`extraVolumeMounts` and relax `securityContext.readOnlyRootFilesystem`.

## Testing the chart

Committed fixtures under `ci/` cover both modes and are used by the
`helm-chart` GitHub Actions workflow:

```sh
helm lint chart/kube-oidc-proxy -f chart/kube-oidc-proxy/ci/single-issuer-values.yaml
helm template t chart/kube-oidc-proxy -f chart/kube-oidc-proxy/ci/multi-issuer-values.yaml
```

## See also

- [Getting started](../../docs/getting-started.md)
- [Multi-issuer authentication](../../docs/multi-issuer.md)
- [Configuration reference](../../docs/configuration.md)
- [Operations: security](../../docs/operations.md#security)
