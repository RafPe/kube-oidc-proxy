# kube-oidc-proxy Helm chart

Helm chart for [`kube-oidc-proxy`](https://github.com/rafpe/kube-oidc-proxy) — a
reverse proxy that authenticates requests with OpenID Connect (OIDC) and
impersonates the authenticated user against the Kubernetes API server.

The chart supports the proxy's two **mutually exclusive** authentication modes:

- **Single-issuer** — the classic `--oidc-*` flags. Set `oidc.clientId`,
  `oidc.issuerUrl` and `oidc.usernameClaim`, or use `oidc.existingSecret`.
- **Multi-issuer** — a Kubernetes `AuthenticationConfiguration`. Set
  `authenticationConfig.content` or `authenticationConfig.existingSecret` (and optionally `readinessRequireAllIssuers`).

When `authenticationConfig.content` or `authenticationConfig.existingSecret` is non-empty the chart passes
`--authentication-config` and omits issuer-specific `--oidc-*` flags.
`oidc.tlsClient` remains available because its credentials apply to every
issuer in either mode.

- [Prerequisites](#prerequisites)
- [Install](#install)
- [Values](#values)
- [Examples](#examples)
- [Security](#security)
- [See also](#see-also)

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
  --namespace kube-oidc-proxy --create-namespace \
  --set oidc.clientId=my-client \
  --set oidc.issuerUrl=https://accounts.google.com \
  --set oidc.usernameClaim=email
```

Or with a values file:

```sh
helm install kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  --namespace kube-oidc-proxy --create-namespace -f my-values.yaml
```

Upgrade with the same values file rather than `--reuse-values`, which renders
with the values stored by the previous release and does not pick up defaults
added by a newer chart:

```sh
helm upgrade kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  --namespace kube-oidc-proxy -f my-values.yaml
```

Uninstall:

```sh
helm uninstall kube-oidc-proxy --namespace kube-oidc-proxy
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

Ignored when either multi-issuer configuration source is set.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `oidc.existingSecret` | string | `""` | Existing Secret in the release namespace supplying the required single-issuer fields. Mutually exclusive with `authenticationConfig`. |
| `oidc.secretKeys` | map | `{}` | Secret key mappings for `clientId`, `issuerUrl`, `usernameClaim`, `usernamePrefix`, `groupsClaim`, `groupsPrefix`, and `signingAlgs`. Requires `existingSecret`. See [Single-issuer from an existing Secret](#single-issuer-from-an-existing-secret). |
| `oidc.clientId` | string | `""` | OIDC client ID expected in the token audience. |
| `oidc.issuerUrl` | string | `""` | OIDC issuer URL (must serve a discovery document). |
| `oidc.usernameClaim` | string | `""` | Token claim used as the username. |
| `oidc.caPEM` | string | `nil` | PEM CA that verifies the issuer TLS connection. |
| `oidc.usernamePrefix` | string | `nil` | Prefix prepended to usernames. |
| `oidc.groupsClaim` | string | `nil` | Token claim carrying groups. |
| `oidc.groupsPrefix` | string | `nil` | Prefix prepended to group names. |
| `oidc.signingAlgs` | list | `[RS256]` | Accepted JWT signing algorithms. |
| `oidc.requiredClaims` | map | `{}` | Claims that must equal a value. Each entry becomes a repeatable `--oidc-required-claim=k=v` flag. |

### Single-issuer from an existing Secret

Create the Secret in the release namespace, for example `auth`. These example
values describe the expected token identity; the proxy does not use an OIDC
client password.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: proxy-oidc
  namespace: auth
type: Opaque
stringData:
  client-id: my-client
  issuer-url: https://accounts.google.com
  username-claim: email
  groups-claim: groups
```

Reference its keys in your Helm values:

```yaml
oidc:
  existingSecret: proxy-oidc
  secretKeys:
    clientId: client-id
    issuerUrl: issuer-url
    usernameClaim: username-claim
    groupsClaim: groups-claim
```

The required fields are `clientId`, `issuerUrl`, and `usernameClaim`. Without a
custom mapping (or with an empty/null mapping), their keys default to
`oidc.client-id`, `oidc.issuer-url`, and `oidc.username-claim`. Leave the three
matching inline values empty, including values carried over during upgrades.
The Secret must have a different name from the chart's `<fullname>-config` Secret.

Mapping `usernamePrefix`, `groupsClaim`, `groupsPrefix`, or `signingAlgs` enables
that field's flag and reads its value from the external Secret. Clear the
matching inline value or Helm fails with a source-conflict error. Unmapped
optional fields retain their inline behavior. For external signing algorithms,
use a comma-separated Secret value (for example `RS256,ES256`) and explicitly
clear the default:

```yaml
oidc:
  existingSecret: proxy-oidc
  signingAlgs: []
  secretKeys:
    signingAlgs: signing-algs
```

This last example uses the default required key names. Without a signing
algorithm mapping, the existing `signingAlgs: [RS256]` default still applies.

Kubernetes injects each selected key through `secretKeyRef` into the matching
`OIDC_*` environment variable; the Pod's arguments expand those variables into
`--oidc-*` flags. This is chart wiring: the binary does not automatically read
`OIDC_*` variables outside this Pod specification. Generic `extraEnv` and
`envFrom` are not chart options.

The chart does not create, read, or update the external Secret. It still creates
its configuration Secret for inline values such as signing algorithms and CA
certificates. `oidc.caPEM` remains a mounted file, `oidc.requiredClaims` remains
an inline map rendered as repeated flags, and `oidc.tlsClient.existingSecret`
continues to supply mounted mTLS credentials. Use
`authenticationConfig.existingSecret` when the entire configuration should come
from one file; an `AuthenticationConfiguration` can contain just one issuer.

The external Secret and all selected keys must exist before the Pod starts.
References are required, so missing keys prevent container startup. Helm does
not inspect their contents. No additional Secret API permissions are needed by
the proxy's ServiceAccount. Restart the Deployment after updating the external
Secret, for example `kubectl -n auth rollout restart deployment/<name>`; external
content is not included in the Helm configuration checksum, and environment
variables do not refresh in running containers. Inline configuration retains
its checksum-based rollout behavior.

### Authentication — multi-issuer

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `authenticationConfig.content` | string | `""` | YAML of an `AuthenticationConfiguration`. When set, `--authentication-config` is used and issuer-specific `--oidc-*` flags are omitted. Format and recipes: [multi-issuer authentication](../../docs/multi-issuer.md), [integrations](../../docs/integrations.md). |
| `authenticationConfig.existingSecret` | string | `""` | Existing Secret in the release namespace. Mutually exclusive with `content`. |
| `authenticationConfig.key` | string | `"authentication-config.yaml"` | Key in the existing Secret containing the configuration. Empty or omitted uses the default. Ignored for inline content. |
| `readinessRequireAllIssuers` | bool | `false` | Require every issuer to initialize before the pod is ready. Default: ready once at least one initializes. |
| `rbac.userExtras` | list | `[]` | Extra user-info keys the proxy's ServiceAccount may impersonate (`userextras/<key>`), in addition to every `claimMappings.extra[].key` in `authenticationConfig.content` and every key in `extraImpersonationHeaders.headers`, which the chart grants automatically. Also required for extra claim keys in an existing configuration Secret, which Helm cannot inspect. Lowercased. |

### OIDC issuer mutual TLS (both modes)

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `oidc.tlsClient.existingSecret` | string | `""` | Existing Secret containing the client certificate/key used for mTLS to every configured OIDC issuer, in either mode. Projected Secret updates are picked up without a restart. |
| `oidc.tlsClient.certKey` | string | `"tls.crt"` | Certificate key in `oidc.tlsClient.existingSecret`. |
| `oidc.tlsClient.keyKey` | string | `"tls.key"` | Private-key key in `oidc.tlsClient.existingSecret`. |

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
| `logging.format` | string | `""` | Log output format (`--logging-format`): `json` or `text`. Empty renders no flag, leaving the binary default of `json`. |
| `logging.verbosity` | int or `""` | `""` | Log verbosity (`--v`). `0` shows lifecycle, access records and warnings; `1` and above add request internals. Empty renders no flag, leaving the binary default of `0`, which also keeps the command line valid for an `image.tag` pinned to a release older than `--logging-format`. Rendered before `extraArgs`, so an `extraArgs` entry of the same flag still wins. |

### Metrics

Off by default. Enabling renders `--metrics-bind-address`, a named container
port, and a dedicated ClusterIP Service `<release>-metrics`; the port is never
added to the main Service. The endpoint is plain HTTP and reveals traffic shape
and health, never identities; see the [metrics reference](../../docs/metrics.md).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `metrics.enabled` | bool | `false` | Serve Prometheus metrics on a dedicated listener. The listener also runs when `metrics.serviceMonitor.enabled` is true. With both switches false the command line stays unchanged for older pinned images. |
| `metrics.bindAddress` | string | `""` | `--metrics-bind-address`; empty derives `0.0.0.0:<metrics.port>`. With either metrics or ServiceMonitor enabled it must end in `:<metrics.port>` and `extraArgs` may not carry the same flag; when both `metrics.enabled` and `metrics.serviceMonitor.enabled` are false, listener settings (`bindAddress`, `port`, `portName`, `tls`, `authentication`) are not validated. ServiceMonitor limits are validated only when the monitor is enabled. |
| `metrics.port` | int | `9090` | Container and Service port. Must be a whole number between 1 and 65535 and differ from 8443 and 8080; a fractional or non-numeric value fails to render. |
| `metrics.portName` | string | `metrics` | Name of the container and Service port the ServiceMonitor references. A valid `IANA_SVC_NAME`, as Kubernetes requires: 1-15 lowercase alphanumerics and dashes, at least one letter, no leading or trailing dash and no consecutive dashes. |
| `metrics.service.labels` / `.annotations` | map | `{}` | Added to the metrics Service. |
| `metrics.serviceMonitor.enabled` | bool | `false` | Enable the metrics listener, dedicated Service and `monitoring.coreos.com/v1` ServiceMonitor with one switch, even when `metrics.enabled` is false. Needs the Prometheus Operator CRDs. See [setup and discovery](../../docs/metrics.md#enable-servicemonitor-scraping). |
| `metrics.serviceMonitor.namespace` | string | `""` | Namespace for the ServiceMonitor; empty uses the release namespace. |
| `metrics.serviceMonitor.additionalLabels` / `.annotations` | map | `{}` | Labels such as `release: kube-prometheus-stack` that your Prometheus selects on. |
| `metrics.serviceMonitor.interval` / `.scrapeTimeout` | string | `""` | Duration strings (`30s`); empty omits the field. |
| `metrics.serviceMonitor.path` / `.scheme` / `.honorLabels` | | `/metrics` / `http` / `false` | Endpoint settings. |
| `metrics.serviceMonitor.jobLabel` / `.targetLabels` / `.podTargetLabels` | | `""` / `[]` / `[]` | Passed through to the spec. |
| `metrics.serviceMonitor.relabelings` / `.metricRelabelings` / `.tlsConfig` | | `[]` / `[]` / `{}` | Passed through to the endpoint. |
| `metrics.serviceMonitor.sampleLimit` / `.targetLimit` / `.labelLimit` | int | `0` | Per-scrape limits protecting Prometheus; 0 omits the field. A negative value fails to render rather than reaching Prometheus. |
| `metrics.podMonitor.enabled` | bool | `false` | PodMonitor alternative that scrapes the pods directly. Mutually exclusive with the ServiceMonitor. |
| `metrics.podMonitor.namespace` / `.additionalLabels` / `.annotations` | | `""` / `{}` / `{}` | Object metadata, as for the ServiceMonitor. |
| `metrics.podMonitor.interval` / `.scrapeTimeout` / `.path` / `.scheme` / `.honorLabels` / `.relabelings` / `.metricRelabelings` | | as ServiceMonitor | Endpoint settings; the PodMonitor has no `tlsConfig` or limit fields. |
| `metrics.prometheusRule.enabled` / `.groups` | bool / list | `false` / `[]` | Optional PrometheusRule; `groups` is rendered as `spec.groups`. No default alerts ship. |
| `metrics.prometheusRule.namespace` / `.additionalLabels` / `.annotations` | | `""` / `{}` / `{}` | Object metadata. |
| `metrics.dashboards.enabled` | bool | `false` | Ship the three Grafana dashboards as a ConfigMap the Grafana sidecar loads. Requires either `metrics.enabled` or `metrics.serviceMonitor.enabled`; when both are false the render fails rather than producing dashboards for a proxy that serves no metrics. |
| `metrics.dashboards.namespace` | string | `""` | Namespace for the ConfigMap; empty uses the release namespace. Set it to Grafana's namespace when its sidecar only watches its own. |
| `metrics.dashboards.label` / `.labelValue` | string | `grafana_dashboard` / `"1"` | The label the Grafana sidecar selects on, and its value. |
| `metrics.dashboards.folder` / `.folderAnnotation` | string | `""` / `grafana_folder` | Grafana folder for the dashboards, set through the sidecar's folder annotation. Empty keeps the sidecar's default folder. |
| `metrics.dashboards.labels` / `.annotations` | map | `{}` | Added to the dashboards ConfigMap. |
| `metrics.tls.enabled`, `metrics.authentication.mode` | | `false`, `none` | Reserved for a later release; any other value fails to render. |
| `networkPolicy.enabled` | bool | `false` | Render a NetworkPolicy admitting only `networkPolicy.metrics.from` to the metrics port, plus the rules in `networkPolicy.additionalIngress`. NetworkPolicies are additive: another policy selecting the proxy pods that already admits the metrics port cannot be narrowed by this one. |
| `networkPolicy.metrics.from` | list | `[]` | NetworkPolicy ingress peers allowed to scrape; required when enabled. |
| `networkPolicy.additionalIngress` | list | admits every peer to 8443 and 8080 | Extra ingress rules rendered after the metrics rule, verbatim. The default keeps the proxy and readiness ports reachable, because selecting the pods isolates all their ingress. Set `[]` when other policies already cover those ports, so this one does not widen them. |

### Dashboards

`metrics.dashboards.enabled` ships three Grafana dashboards in one ConfigMap
labelled `grafana_dashboard: "1"`, which the Grafana sidecar loads with no
further configuration (kube-prometheus-stack enables that sidecar by default;
point `metrics.dashboards.namespace` at Grafana's namespace if its sidecar only
watches its own). They answer different questions - **Overview** for whoever is
on call, **Security & identity** for who is being refused and why, **Capacity &
dependencies** for what holds connections and how the API server behaves - and
each panel carries a description saying what it is for. Screenshots and the
per-panel summary are in the
[metrics reference](../../docs/metrics.md#dashboards).

`hack/verify-chart-dashboards.sh` checks them in CI: the uid, the shared
template variables, a description on every panel, the datasource variable on
every query, that the ConfigMap reproduces each file byte-for-byte, and the
Grafana dashboard linter under `--strict`. **That step needs `git` and network
access**: every published tag of the linter carries a `replace` directive in
its `go.mod`, so `go run <module>@<version>` refuses to build it and the script
builds the pinned tag from a shallow clone instead. Four linter rules are
excluded in `dashboards/.lint`, with the reason recorded there: these
dashboards scope by `$namespace`/`$pod` rather than by scrape job, so they have
no `$job` or `$instance` variables and no job/instance matchers.

### Extra args & volumes

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `extraArgs` | map | `{}` | Extra CLI flags passed as `--key=value`, for anything without a value of its own, such as the audit flags ([auditing](../../docs/auditing.md#enabling-it-with-the-chart)). Rendered last, so an entry here wins over a flag the chart generates. `metrics-bind-address` is the one exception: when either `metrics.enabled` or `metrics.serviceMonitor.enabled` is true it fails the render, because the container port, the metrics Service and the monitors all follow `metrics.port` and would no longer point at the listener. Set `metrics.port` or `metrics.bindAddress` instead. With both switches false, `extraArgs.metrics-bind-address` remains available for manually managed listeners. |
| `extraVolumeMounts` | list | `{}` | Extra container volumeMounts. |
| `extraVolumes` | list | `{}` | Extra pod volumes. |

### Ingress

The proxy only listens on TLS, so an ingress must re-encrypt to the pod, and it
must not cut the long-lived streams `kubectl` uses; the annotations for
ingress-nginx are in [getting started: expose it](../../docs/getting-started.md#3-expose-it).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
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
| `test.image.repository` | string | `docker.io/library/busybox` | Image of the `helm test` connection hook. A value so an image mirror can redirect it. |
| `test.image.tag` | string | `1.37.0` | Tag of the `helm test` connection hook image. |

### Security context (hardened by default)

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `podSecurityContext.runAsNonRoot` | bool | `true` | Require the container to run as a non-root user. |
| `podSecurityContext.runAsUser` | int | `1000` | UID to run as (required because the image sets no `USER`). |
| `podSecurityContext.seccompProfile.type` | string | `RuntimeDefault` | Seccomp profile for the pod. |
| `securityContext.allowPrivilegeEscalation` | bool | `false` | Disallow privilege escalation. |
| `securityContext.readOnlyRootFilesystem` | bool | `true` | Mount the image's root filesystem read-only. Mounted volumes stay writable, so a file audit log only needs an `emptyDir`. |
| `securityContext.capabilities.drop` | list | `[ALL]` | Linux capabilities dropped from the container. |

## Examples

The worked examples live with the guides that explain them: a single-issuer
values file and a private-CA variant under
[authentication: single-issuer with flags](../../docs/authentication.md#single-issuer-with-flags),
serving TLS and an ingress in
[getting started](../../docs/getting-started.md#3-expose-it), and a
multi-replica layout with a PodDisruptionBudget and topology spread in
[operations](../../docs/operations.md#availability-and-issuer-outages).
The chart's own test fixtures under [`ci/`](./ci/) are complete values files
for both configurations.

Accepting tokens from several identity providers is a Kubernetes
`AuthenticationConfiguration`; each issuer's CA (if any) must be inline under
`issuer.certificateAuthority`.

```yaml
# Issuer-specific oidc.* values are not rendered while this is set;
# oidc.tlsClient still applies to every issuer.
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

## Security

The chart runs the proxy with a **hardened SecurityContext by default**:
non-root (`runAsUser: 1000`), read-only root filesystem, all Linux capabilities
dropped, no privilege escalation, and the `RuntimeDefault` seccomp profile. The
proxy is a privileged component — its ServiceAccount can impersonate identities
against the API server — so keep those defaults and restrict who can edit the
Deployment and its RBAC. See [`../../docs/operations.md`](../../docs/operations.md#security).

The API server authorizes each `Impersonate-Extra-<key>` header separately, as
`impersonate` on `userextras/<key>`, and a key the ServiceAccount is not
granted fails the whole request with 403. The chart's ClusterRole therefore
grants every `claimMappings.extra[].key` declared in
`authenticationConfig.content` and every key in
`extraImpersonationHeaders.headers`, read from those values at render time so
the grant cannot drift from the configuration. Keys that clients send
themselves as `Impersonate-Extra-*` headers go in `rbac.userExtras`.

If you enable a feature that writes to the local filesystem (e.g. an
`audit-log-path` to a file), mount an `emptyDir` at that path via
`extraVolumes` / `extraVolumeMounts`. `securityContext.readOnlyRootFilesystem`
can stay `true`: it applies to the image's filesystem, and mounted volumes are
writable regardless.

## See also

- [Getting started](../../docs/getting-started.md)
- [Multi-issuer authentication](../../docs/multi-issuer.md)
- [Configuration reference](../../docs/configuration.md)
- [Operations: security](../../docs/operations.md#security)

### Use an existing authentication Secret

Create the Secret in the namespace where the chart is installed:

```sh
kubectl -n auth create secret generic proxy-auth \
  --from-file=authentication-config.yaml=./authentication-config.yaml
```

The file must contain an `AuthenticationConfiguration`, as shown in the
[multi-issuer guide](../../docs/multi-issuer.md). Configure the chart:

```yaml
authenticationConfig:
  existingSecret: proxy-auth
  key: authentication-config.yaml
rbac:
  userExtras:
    - example.com/team
```

Set `rbac.userExtras` to every `claimMappings.extra[].key` in the file. Helm
cannot read the external configuration to generate these grants. No additional
Secret API permissions are needed by the proxy.

Leave `authenticationConfig.content` empty. The chart mounts the selected key
read-only at `/etc/oidc/authentication-config.yaml` and does not create or manage
the configuration Secret. The Secret and key must exist before the pod starts;
a missing Secret or key prevents the pod from starting.

Configuration is loaded at startup. Restart the Deployment after updating the
Secret, for example with `kubectl -n auth rollout restart deployment/<name>`.
Helm cannot calculate a checksum for external content. Inline configuration
keeps its existing checksum rollout behavior. Single-issuer values and inline
multi-issuer configuration require no changes.
