# Multi-Issuer OIDC Authentication

kube-oidc-proxy can accept JWTs from several OIDC issuers at once using the
standard Kubernetes [Structured Authentication Configuration](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration)
file format — the same format kube-apiserver consumes since Kubernetes 1.30.
This is particularly useful on managed clusters (EKS, GKE, DOKS, ...) where
apiserver flags cannot be changed and only a single (or no) native OIDC
provider can be configured.

- [Enabling](#enabling)
- [Recipes per identity provider](#recipes-per-identity-provider)
- [Security: always use distinct per-issuer prefixes](#security-always-use-distinct-per-issuer-prefixes)
- [Readiness](#readiness)
  - [Issuer records in the log](#issuer-records-in-the-log)
- [Helm](#helm)
- [Notes](#notes)
- [See also](#see-also)

## Enabling

Pass `--authentication-config=/path/to/config.yaml`. This flag is mutually
exclusive with issuer-specific `--oidc-*` flags; the optional OIDC TLS client
certificate/key flags apply to all issuers. Both `apiserver.config.k8s.io/v1` and
`v1beta1` are accepted; the file is strictly validated at startup (unknown
fields, duplicate issuers, and invalid CEL expressions are rejected). Only
the `jwt:` section is supported; `anonymous:` is rejected.

The file is read once at startup. To apply changes, restart the pods — the
Helm chart annotates the Deployment with a config checksum, so editing
`authenticationConfig.content` triggers a rolling restart automatically.

## Recipes per identity provider

Each provider has its own token shape and its own mapping. The recipes,
GitHub Actions, TeamCity, Google service accounts, GKE workloads, an internal
issuer with a private CA and GitLab CI, live in
[integrations](./integrations.md), together with the RBAC that binds the
mapped identities. Every recipe is one entry for the `jwt:` list here; combine
them freely in a single configuration, subject to the prefix rule below.

## Security: always use distinct per-issuer prefixes

All issuers feed the same RBAC namespace. Without distinct prefixes, issuer
B could mint a `sub` or group value that collides with an identity you bound
for issuer A. Give every issuer a unique `prefix:` (or bake a unique prefix
into every CEL expression) and never use `prefix: "-"`-style unprefixed
usernames in a multi-issuer setup.

## Readiness

By default the pod reports ready once at least one issuer's JWKS has been
fetched; issuers still pending are logged and keep initializing in the
background (tokens for them fail with 401 until initialized). Set
`--readiness-require-all-issuers` (Helm: `readinessRequireAllIssuers: true`)
to only report ready when every issuer is initialized. Configuration errors
(invalid YAML, unknown fields, duplicate issuers, bad CEL) always fail
startup, regardless of this flag.

Readiness is about startup. What happens when an issuer becomes unreachable
later, and why cached signing keys mean existing tokens keep working, is in
[operations: availability and issuer outages](./operations.md#availability-and-issuer-outages).

### Issuer records in the log

Issuer state is visible on the normal log stream at the default `-v=0`; you do
not need to raise verbosity to see which issuers are up.

| `event_type` | Level | Fields | Emitted when |
| --- | --- | --- | --- |
| `oidc.issuer.configured` | INFO | `issuer_name`, `issuer_count` | Once per configured issuer at startup. |
| `oidc.issuer.initialized` | INFO | `issuer_name`, `issuer_state=initialized`, `ready_issuers`, `total_issuers` | That issuer's JWKS loaded and it can now validate tokens. |
| `oidc.issuer.pending` | WARN | `issuer_name`, `issuer_state=pending`, `pending_reason`, `ready_issuers`, `total_issuers` | The pending set or a pending reason **changed**. Not emitted on every readiness scrape, so the newest record per `issuer_name` is that issuer's current state. |
| `readiness.proxy.ready` | INFO | `ready_issuers`, `total_issuers`, `readiness_mode` | Readiness latched to ready. `readiness_mode` is `any` or `all`, mirroring `readinessRequireAllIssuers`. |

`pending_reason` is one of `not_initialized` (the first fetch has not finished
yet), `transient` (the JWKS endpoint is failing but the fetch is being retried),
or `error`. `ready_issuers`/`total_issuers` on any of these records tells you
how far initialization has got without reading the probe.

`issuer_name` is the **configured** issuer name, bounded to 256 characters and
sanitized. The full issuer URL is never logged, on any record. The same
`issuer_name` also appears on `request.access.decided`, which is how you tell
which issuer accepted a given token:

```bash
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy --since=1h \
  | jq -r 'select(.event_type == "request.access.decided" and .event == "AuSuccess")
           | .issuer_name' \
  | sort | uniq -c
```

To see each issuer's current state in one pod, take the newest of its
`pending` and `initialized` records:

```bash
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy \
  | jq -rs 'map(select(.event_type == "oidc.issuer.pending" or .event_type == "oidc.issuer.initialized"))
            | group_by(.issuer_name) | map(last)
            | .[] | "\(.issuer_name)\t\(.issuer_state)\t\(.pending_reason // "-")\t\(.ready_issuers)/\(.total_issuers)"'
```

The [logging reference](./logging.md) has the equivalent LogQL and Splunk
queries and the full field reference.

## Helm

```yaml
authenticationConfig:
  content: |
    apiVersion: apiserver.config.k8s.io/v1
    kind: AuthenticationConfiguration
    jwt:
    - issuer:
        url: https://token.actions.githubusercontent.com
        audiences: ["kube-oidc-proxy.example.com"]
      claimMappings:
        username:
          expression: '"gha:" + claims.repository + ":" + claims.ref'
        groups:
          expression: '["gha:org:" + claims.repository_owner]'
      claimValidationRules:
      - expression: 'claims.repository_owner_id == "1234567"'
        message: "token not issued for the expected organisation"
    - issuer:
        url: https://auth.internal.example.com
        audiences: ["kubernetes"]
      claimMappings:
        username: {claim: sub, prefix: "sys-a:"}
        groups:   {claim: groups, prefix: "sys-a:"}
readinessRequireAllIssuers: false
```

If an issuer declares `claimMappings.extra`, the proxy forwards each key as an
`Impersonate-Extra-<key>` header and the API server authorizes every one of
them separately, as `impersonate` on `userextras/<key>`. The chart reads the
keys out of `authenticationConfig.content` (and out of
`extraImpersonationHeaders.headers`) and grants them in its ClusterRole, so
nothing extra is needed there; `rbac.userExtras` covers keys that clients send
themselves. Installing without the chart, grant them yourself, or every
request carrying an extra fails with 403:

```yaml
- apiGroups: ["authentication.k8s.io"]
  resources: ["userextras/github.com/actor", "userextras/github.com/run-id"]
  verbs: ["impersonate"]
```

## Notes

- Signing algorithms: with `--authentication-config`, all valid JOSE signing
  algorithms are accepted (matching kube-apiserver); `--oidc-signing-algs`
  applies only to the single-issuer flag mode.
- Issuer JWKS endpoints must be reachable from the proxy pod network (not
  from the control plane), so private internal issuers work.
- Each issuer entry may carry its own `certificateAuthority` inline.

## See also

- [Getting started](./getting-started.md) — install and choose an auth mode.
- [Configuration reference](./configuration.md) — all flags and impersonation.
- [Local multi-issuer test: kind and GitHub Actions](./development.md#local-multi-issuer-test-kind-and-github-actions).
- [Architecture: union authenticator](./architecture.md#multi-issuer-union-authenticator).
- [Logging reference](./logging.md) — the `oidc.issuer.*` records and how to
  query them.
