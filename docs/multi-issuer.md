# Multi-Issuer OIDC Authentication

kube-oidc-proxy can accept JWTs from several OIDC issuers at once. The
configuration file has one of two kinds:

- The upstream kind `apiserver.config.k8s.io` `AuthenticationConfiguration`.
  This is the Kubernetes [Structured Authentication Configuration](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration)
  format that kube-apiserver reads since Kubernetes 1.30.
- The proxy kind `kube-oidc-proxy.rafpe.github.io/v1alpha1`
  `AuthenticationConfiguration`. Only kube-oidc-proxy reads this kind.
  [Choose a kind](#choose-a-kind) tells you which kind to use.

This is particularly useful on managed clusters (EKS, GKE, DOKS, ...) where
apiserver flags cannot be changed and only a single (or no) native OIDC
provider can be configured.

- [Enabling](#enabling)
- [Choose a kind](#choose-a-kind)
- [Several audiences for one issuer](#several-audiences-for-one-issuer)
- [Several issuers for one issuer URL](#several-issuers-for-one-issuer-url)
  - [Move from the upstream kind](#move-from-the-upstream-kind)
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
certificate/key flags apply to all issuers. The proxy accepts three
`apiVersion` values:

- `apiserver.config.k8s.io/v1` and `apiserver.config.k8s.io/v1beta1`, the
  upstream kind.
- `kube-oidc-proxy.rafpe.github.io/v1alpha1`, the proxy kind.

The proxy validates the file strictly at startup. It refuses unknown fields
and invalid CEL expressions. The upstream kind refuses two issuers on one host.
The proxy kind accepts several issuers on one issuer URL, with the limits in
[Several issuers for one issuer URL](#several-issuers-for-one-issuer-url). The
upstream kind supports only the `jwt:` section. The proxy refuses `anonymous:`.

The file is read once at startup. To apply changes, restart the pods — the
Helm chart annotates the Deployment with a config checksum, so editing
`authenticationConfig.content` triggers a rolling restart automatically.

## Choose a kind

Use the upstream kind when it can express your configuration. Use the proxy
kind when you need a feature that only the proxy kind has.

| Need | Kind |
|---|---|
| kube-apiserver must also load the same file | upstream |
| Each issuer URL has one `jwt` entry, and each host has one issuer | upstream |
| Several issuers for one issuer URL, selected by the token audience | proxy |
| Several issuers on one host, for example two GKE or EKS cluster issuers | proxy |
| An `issuer_name` that you set, not the host of the issuer URL | proxy |
| The issuer name in CEL with `authenticationConfiguration.issuer.name` | proxy |

The two kinds use the same `jwt` entry. The proxy kind puts each entry under
`issuers[].jwt` and adds a `name`. A token from one issuer URL gets the same
result in both kinds, unless several issuers of the proxy kind share that URL.
[Move from the upstream kind](#move-from-the-upstream-kind) gives the steps.

## Several audiences for one issuer

An issuer entry may list more than one audience. A token is accepted when
its `aud` claim, a string or a list, contains at least one of them. Listing
several requires `audienceMatchPolicy: MatchAny`, the only policy the API
defines; the proxy refuses to start otherwise, with
`audienceMatchPolicy must be MatchAny for multiple audiences`. With a single
audience the field may be left out. Audiences are scoped to their entry: a
value accepted for one issuer does not admit tokens from another.

```yaml
jwt:
  - issuer:
      url: https://token.actions.githubusercontent.com
      audiences:
        - kube-oidc-proxy.example.com
        - kube-oidc-proxy-legacy.example.com   # kept while workflows migrate
      audienceMatchPolicy: MatchAny
    claimMappings:
      username:
        expression: '"gha:" + claims.repository + ":" + claims.ref'
```

Typical uses are rotating an audience without a flag day, and one proxy
serving clients that request tokens for different audience strings. Both
kube-apiserver's audience rules apply: each value must be non-empty and unique
within its entry.

## Several issuers for one issuer URL

One issuer URL can sign tokens for more than one trust group. For example,
`https://token.actions.githubusercontent.com` signs tokens for the workflows of
every GitHub organization. The upstream format accepts only one entry per
issuer URL. For several trust groups on one issuer URL, use the proxy kind
`kube-oidc-proxy.rafpe.github.io/v1alpha1` `AuthenticationConfiguration`:

```yaml
apiVersion: kube-oidc-proxy.rafpe.github.io/v1alpha1
kind: AuthenticationConfiguration
issuers:
- name: gha-internal
  jwt:
    issuer:
      url: https://token.actions.githubusercontent.com
      audiences: ["kube-oidc-proxy-internal"]
    claimMappings:
      username:
        expression: 'authenticationConfiguration.issuer.name + ":" + claims.repository + ":" + claims.ref'
    claimValidationRules:
    - expression: 'claims.repository_owner_id == "1234567"'
      message: "only the internal organization"
- name: gha-vendor
  jwt:
    issuer:
      url: https://token.actions.githubusercontent.com
      audiences: ["kube-oidc-proxy-vendor"]
    claimMappings:
      username:
        expression: 'authenticationConfiguration.issuer.name + ":" + claims.repository + ":" + claims.ref'
    claimValidationRules:
    - expression: 'claims.repository_owner_id == "7654321"'
      message: "only the vendor organization"
```

Each item of `issuers` has these fields:

- `name`: the `issuer_name` of the issuer in logs and metrics. It must be a
  DNS-1123 subdomain (lowercase letters, digits, `-` and `.`, at most 253
  characters). It must be unique in the document.
- `jwt`: one entry of the upstream `jwt` list, in the
  `apiserver.config.k8s.io/v1` form.

### The issuer name in CEL

The CEL expressions of an issuer can use `authenticationConfiguration.issuer.name`.
Its value is the `name` of that issuer. In the example above, the two
issuers have the same username expression. The usernames start with
`gha-internal:` and `gha-vendor:`.

- At startup, the proxy replaces each reference with a string literal of the
  name. Then the upstream validation runs. The same text inside a string
  literal stays.
- The variable works in each expression field: `claimValidationRules`,
  `claimMappings` (`username`, `groups`, `uid` and `extra`) and
  `userValidationRules`.
- `prefix` is not CEL, so the variable does not work there. To put the name
  in the username, use the expression form of the mapping.
- `issuer.name` is the only field. `authenticationConfiguration.issuer.url`
  and each other use of `authenticationConfiguration` stop the startup. The
  error gives the path of the expression, for example
  `issuers[0].jwt.claimMappings.username.expression`.
- `authenticationConfiguration` cannot be the variable of a macro, for
  example in `claims.groups.exists(authenticationConfiguration, ...)`. The
  startup stops with `cannot be a macro variable`.
- The upstream kind and kube-apiserver do not define the variable. There, the
  expression fails with `undeclared reference`.

The proxy refuses to start in these conditions:

- A `name` is not a DNS-1123 subdomain, or two issuers have the same `name`.
- Two issuers have the same issuer URL and share an audience.
- Two issuers have the same non-empty `discoveryURL`.
- A `jwt` entry fails the upstream validation. The error names the issuer as
  `issuers[i]`.

The proxy selects the issuer for a token in these steps:

1. It reads `iss` and `aud` from the token without verification.
2. If no issuer has the URL `iss`, no issuer verifies the token. The proxy
   rejects the token as a token of an unknown issuer, not with
   `reason=audience_unrouted`.
3. If one issuer has the URL `iss`, that issuer verifies the token. The `aud`
   claim has no effect on the selection.
4. If several issuers have the URL `iss`, the issuer whose `audiences`
   contain a value of `aud` verifies the token.
5. If several issuers have the URL `iss` and `aud` matches no issuer or more
   than one issuer, the proxy rejects the token. The `authn.oidc.failed`
   record carries `reason=audience_unrouted`. No issuer verifies the token.

> [!WARNING]
> The audience is routing, not authorization. The client chooses `aud`, so a
> vendor workflow can request the audience of the internal issuer. Each issuer
> must pin its trust group with an immutable claim in `claimValidationRules`.
> For GitHub Actions, use `repository_owner_id`. For Google, use `sub`, or the
> email domain together with `email_verified`.
>
> The proxy does not refuse this at startup. It starts with an issuer that has
> no `claimValidationRules`, also when that issuer shares its issuer URL with
> another issuer. Then any token of that issuer URL with the audience of that
> issuer gets the mappings and the RBAC of that issuer.

The proxy kind also gives different names to issuers on one host, for example
two GKE or EKS cluster issuers. The upstream kind refuses issuers on one host,
because it names each issuer by its host.

A file of the proxy kind does not load in kube-apiserver. A file that must
load in kube-apiserver can select the trust group in CEL inside one entry
instead. ADR-0001 ([`docs/decisions/0001-route-same-issuer-entries-by-audience.md`](https://github.com/RafPe/kube-oidc-proxy/blob/main/docs/decisions/0001-route-same-issuer-entries-by-audience.md))
compares the two options.

### Move from the upstream kind

Do these steps to change a file of the upstream kind to the proxy kind:

1. Set `apiVersion` to `kube-oidc-proxy.rafpe.github.io/v1alpha1`.
2. Keep `kind: AuthenticationConfiguration`.
3. Change the `jwt` key to `issuers`.
4. Move each old `jwt` entry under the `jwt` key of one item of `issuers`.
5. Give each item a `name`.
6. Restart the proxy and make sure that each issuer reports ready.

Before:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://token.actions.githubusercontent.com
    audiences: ["kube-oidc-proxy"]
  claimMappings:
    username:
      expression: '"gha:" + claims.repository'
```

After:

```yaml
apiVersion: kube-oidc-proxy.rafpe.github.io/v1alpha1
kind: AuthenticationConfiguration
issuers:
- name: token.actions.githubusercontent.com
  jwt:
    issuer:
      url: https://token.actions.githubusercontent.com
      audiences: ["kube-oidc-proxy"]
    claimMappings:
      username:
        expression: '"gha:" + claims.repository'
```

The upstream kind uses the host of the issuer URL as `issuer_name`. The proxy
kind uses the `name` of each issuer. The bundled dashboards show any issuer
name, and their `$issuer` variable lists the names that the proxy reports. Only
your own queries and alerts that filter on the old host see a new value.

The example above sets `name` to the host, so the `issuer_name` does not change.
A host with a port, for example `dex.example.com:5556`, is not a valid `name`,
because `:` is not valid in a DNS-1123 subdomain.

The `jwt` entry of the proxy kind has the `apiserver.config.k8s.io/v1` form. A
`v1beta1` entry has the same fields.

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
into every CEL expression, for example with
`authenticationConfiguration.issuer.name` in the proxy kind) and never use unprefixed usernames (`prefix: ""`)
in a multi-issuer setup. The prefix is prepended verbatim: `prefix: "-"` is
not an opt-out, it makes every username start with `-`.

## Readiness

By default the pod reports ready once at least one issuer's JWKS has been
fetched; issuers still pending are logged and keep initializing in the
background (tokens for them fail with 401 until initialized). Set
`--readiness-require-all-issuers` (Helm: `readinessRequireAllIssuers: true`)
to only report ready when every issuer is initialized. Configuration errors
(invalid YAML, unknown fields, conflicting issuers, bad CEL) always fail
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
yet) or `transient` (the JWKS endpoint is failing but the fetch is being
retried). `ready_issuers`/`total_issuers` on any of these records tells you
how far initialization has got without reading the probe.

`issuer_name` is the `name` of the issuer for the proxy kind. For the upstream
kind and for the `--oidc-*` flags, it is the **host** of the configured issuer
URL, bounded to 256 characters and sanitized. The proxy's own records never carry the full issuer
URL, except a `proxy.startup.failed` for an issuer configuration the Kubernetes
JWT authenticator rejects; bridged `component=k8s` records from that
authenticator can quote it as well (see
[logging: redaction](./logging.md#redaction)). The same
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

The [logging reference](./logging.md#issuer-state) has the Splunk equivalent,
the LogQL history and metric forms, and the full field reference.

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
- [Architecture: issuer router](./architecture.md#multi-issuer-router).
- [Logging reference](./logging.md) — the `oidc.issuer.*` records and how to
  query them.
