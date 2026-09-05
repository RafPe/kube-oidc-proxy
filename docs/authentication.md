# Authentication and identity

How the proxy decides who a request is, and what it does with that identity
afterwards. Read this once before choosing a configuration; the
[configuration reference](./configuration.md) then lists every flag, and
[integrations](./integrations.md) has the recipe for each identity provider.

- [Choosing a configuration](#choosing-a-configuration)
  - [Single-issuer with flags](#single-issuer-with-flags)
  - [Structured configuration, one or many issuers](#structured-configuration-one-or-many-issuers)
- [Impersonation model](#impersonation-model)
  - [Inbound impersonation (`kubectl --as`)](#inbound-impersonation-kubectl---as)
  - [SubjectAccessReview caching and the header value cap](#subjectaccessreview-caching-and-the-header-value-cap)
  - [Reserved `system:` identities](#reserved-system-identities)
  - [Original-user audit headers](#original-user-audit-headers)
- [Token passthrough](#token-passthrough)
  - [TokenReview caching](#tokenreview-caching)
- [No impersonation](#no-impersonation)
- [Extra impersonation headers](#extra-impersonation-headers)
- [Glossary](#glossary)
- [Common questions](#common-questions)
- [See also](#see-also)

## Choosing a configuration

Four independent choices shape how the proxy authenticates, and they are easy
to conflate because two of them share the word "mode".

| You need | Configure | Notes |
| --- | --- | --- |
| One issuer, configured with flags | `oidc.clientId`, `oidc.issuerUrl`, `oidc.usernameClaim` (the `--oidc-*` flags) | Mirrors the API server's own OIDC flags one-to-one. Username and group prefixes, required claims and signing algorithms are flags too. |
| One or more issuers, with claim expressions and validation rules | `authenticationConfig.content` (`--authentication-config`) | The Kubernetes `AuthenticationConfiguration` format. Worth using for a single issuer as soon as you need CEL: synthesized groups, `extra` for audit, numeric-ID pinning. Mutually exclusive with the flags above. |
| Bearer tokens that are not OIDC tokens, such as ServiceAccount tokens | `tokenPassthrough` (`--token-passthrough`, alpha) | Tried only after OIDC validation fails; validated with a `TokenReview` and forwarded without impersonation. Independent of the two choices above. |
| Forward authenticated requests without impersonating | `--disable-impersonation` (alpha) | The API server authenticates the request itself. Rarely wanted; see [No impersonation](#no-impersonation). |

The first two are the mutually exclusive pair. The binary refuses to start
when both `--authentication-config` and issuer-specific `--oidc-*` flags are
given; the chart never renders both, and `oidc.tlsClient` is the one `oidc.*`
value that applies to every issuer in either configuration.

### Single-issuer with flags

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

### Structured configuration, one or many issuers

Accept tokens from one or several identity providers via a Kubernetes
`AuthenticationConfiguration`, with CEL expressions for usernames, groups,
`extra` values and validation rules. The
[multi-issuer guide](./multi-issuer.md) covers the format, readiness and the
per-issuer prefix rule; [integrations](./integrations.md) has a recipe per
provider.

## Impersonation model

`kube-oidc-proxy` forwards authenticated requests to the API server by
[impersonating](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)
the end user: it authenticates as its **own ServiceAccount** and attaches
`Impersonate-User` / `Impersonate-Group` / `Impersonate-Extra-*` headers for the
mapped identity. Impersonation **replaces, but does not bypass, RBAC** — the API
server still authorizes the impersonated identity.

### Inbound impersonation (`kubectl --as`)

The proxy also honours impersonation headers on **inbound** requests, so
`kubectl --as` works through it. Nobody can become anybody: an impersonating
request is authorized twice, and both checks deny by default.

1. **The proxy asks whether the caller may impersonate.** For every inbound
   `Impersonate-*` header value it sends a `SubjectAccessReview` to the API
   server asking whether the **authenticated** identity, the one the token
   mapped to, holds the `impersonate` verb on that value. A single refused
   value fails the whole request with `403` and
   `reason=impersonation_denied`; nothing is forwarded. These are the
   decisions the [SubjectAccessReview cache](./caching.md#subjectaccessreview-decision-cache)
   remembers.
2. **The API server authorizes the target.** The request is forwarded
   impersonating the target identity, so RBAC applies to the target, not to
   the caller. A target with no bindings can do nothing.

Each header value is a separate authorization against a separate resource,
which is what a grant has to name:

| Header | Authorized as `impersonate` on |
| --- | --- |
| `Impersonate-User` | `users`, core API group |
| `Impersonate-Group` | `groups`, core API group |
| `Impersonate-Uid` | `uids`, `authentication.k8s.io` |
| `Impersonate-Extra-<key>` | `userextras/<key>`, `authentication.k8s.io`; the key is lowercased first |

kubectl sends only the headers you ask for, so `--as=<user>` alone sends one
user header and needs only a `users` rule; `--as-group` adds a `groups` check
per group. Grant impersonation as narrowly as the use case allows. A `users`
rule with no `resourceNames` permits impersonating any user, `cluster-admin`
holders included; with `resourceNames` it permits exactly the names listed.
Note that the `system:` guard described below applies to the **authenticated**
identity, not to impersonation targets: a binding that permits impersonating
`system:masters` is honoured, on the assumption that it was granted on purpose.

A minimal grant, letting one CI identity act as a fixed read-only user:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonate-ci-viewer
rules:
- apiGroups: [""]
  resources: ["users"]
  resourceNames: ["ci-viewer"]        # this username only
  verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-impersonate-ci-viewer
subjects:
- kind: Group
  name: "gha:repo:my-org/my-repo"     # who may impersonate
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: impersonate-ci-viewer
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-viewer-view
subjects:
- kind: User
  name: ci-viewer                     # what the target may do
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
```

With that in place, `kubectl --token=<ci token> --as=ci-viewer get pods` is
allowed by the proxy and authorized by the API server as `ci-viewer`. Two
consequences of the model are easy to miss:

- **Nothing is hidden by impersonating.** The proxy's access record carries
  the caller as `inbound_user` and the target as `outbound_user`, and the
  API server's audit event carries the target as `impersonatedUser` next to
  the [original-user headers](#original-user-audit-headers) naming the caller.
- **Revocation lags by the cache TTL.** Removing an impersonation binding is
  enforced through the proxy only once the cached allow expires, up to
  `--subject-access-review-cache-allow-ttl`.

**When `--as` is worth using.** For most callers it is not: an identity whose
claim mappings already put it in the right groups has its permissions without
an extra hop, and binding roles to those groups is the better default.
Impersonation earns its place in a few situations:

- **Testing RBAC without owning the identity.** Before a binding goes live,
  an operator checks what it grants with
  `kubectl auth can-i --list --as=<user>` or `--as-group=<group>`. No token
  to obtain, and the answer is exact because the API server evaluates it for
  that identity.
- **Break-glass with a trail.** People hold a low-privilege identity day to
  day and a narrow grant lets them impersonate an admin identity when needed.
  Every such request is audited with the person in the original-user headers
  and the admin identity as the target, so escalation is visible per request
  instead of being a standing permission.
- **A service acting on behalf of its callers.** A deployment portal or a
  GitOps service authenticates once as itself and impersonates the requesting
  user on each call. The API server enforces the caller's RBAC, not the
  service's, so the service cannot be talked into doing what its caller
  could not, and the audit log names the caller.
- **Reduced privilege for one job.** A broadly privileged identity
  impersonates a narrow one for a risky step. Requests a migration runner
  makes as `payments-migrator`, bound in one namespace, are limited to that
  namespace. This bounds what the script does through that path; it does not
  bound what the credential could do if used directly.
- **One credential, several roles.** A shared CI token maps to one identity,
  and different pipelines impersonate different team users with their own
  bindings. Access is partitioned by an RBAC rule rather than by minting more
  credentials.

Impersonation never exceeds the target's permissions and never hides who
acted. Whether a `system:` target is reachable is decided by RBAC alone, as
noted above.

### SubjectAccessReview caching and the header value cap

Impersonation authorization decisions are served from a bounded in-memory cache
(`--subject-access-review-cache-allow-ttl` /
`--subject-access-review-cache-deny-ttl`, both `10s` by default), and the
number of impersonation header values accepted per request is capped
(`--max-impersonation-header-values`, default `64`; over-cap requests are
rejected with HTTP 431 before any review is sent). The flows, cache semantics,
and tuning tradeoffs — revocation and grant lag in particular — are documented
in [Caching and API-server protection](./caching.md).

### Reserved `system:` identities

Kubernetes reserves the `system:` prefix for its own identities: `system:masters`
is bound to `cluster-admin` by default, and `system:serviceaccount:<ns>:<name>`
is any service account. The chart grants the proxy `impersonate` on `users`,
`groups` and `serviceaccounts` without `resourceNames`, so an identity carrying
one of those values is impersonated as-is.

Kubernetes does **not** guard this on claim mappings. By default the proxy
therefore refuses, with `403`, any authenticated request whose identity carries
the reserved prefix:

| Field | Rule |
| --- | --- |
| Username | Every `system:`-prefixed value is refused — no exceptions, including `system:authenticated`, which an RBAC binding can name as a `User`. |
| Groups | `system:authenticated` is permitted (the proxy appends it to every request itself); any other `system:` group is refused. |

The check runs in the authentication handler, **before** the `SubjectAccessReview`
that authorizes inbound impersonation — that review is built with the requester's
own groups, so a forged `system:` group would otherwise feed the authorization
decision and not merely the impersonation headers. The identity is refused rather
than silently stripped: a caller served without the group they claimed has been
told the wrong thing about who they are. The rejection is audited against the
identity that was presented.

Because the check sits in the authentication handler, it applies to **every**
authenticated request, including under `--disable-impersonation`, where such a
request was previously forwarded for the API server to authenticate itself. It
does not apply to requests authenticated by `--token-passthrough`: those never
reach the OIDC claim mapping, and the API server validates the token itself.

This is defense in depth. The operator-side mitigations remain the primary
control and are unchanged: set `--oidc-groups-prefix` (and
`--oidc-username-prefix`) so claims cannot collide with cluster identities, or
express `userValidationRules` in an `--authentication-config` document. The proxy
refuses to start when either prefix flag itself begins with `system:`.

`Impersonate-*` targets authorized by `SubjectAccessReview` are deliberately left
alone: an operator who bound RBAC permitting impersonation of `system:masters`
made that call on purpose, and blocking it would break break-glass access.

If a directory legitimately holds a `system:`-prefixed group, name it in
`--allow-reserved-groups`:

```text
--allow-reserved-groups=system:monitoring,system:logging
```

Only the groups listed are permitted; every other reserved group is still
refused, and there is no way to permit a reserved **username** — a reserved
username has no legitimate use, and `system:serviceaccount:<namespace>:<name>`
is the most direct path to another identity's privileges. Each entry must itself
start with `system:`; the proxy refuses to start otherwise, because listing an
unreserved group has no effect and is almost certainly a typo.

### Original-user audit headers

Whenever the proxy impersonates, it attaches `Extra` headers identifying the
**original** authenticated user, so the API server's audit log records who really
made the request:

| Extra key | When it is sent | Description |
| --- | --- | --- |
| `originaluser.jetstack.io-user` | Always (when impersonating) | The original username. |
| `originaluser.jetstack.io-groups` | When the original user has ≥1 group | The original groups. |
| `originaluser.jetstack.io-uid` | When the original user has a UID | The original user UID. |
| `originaluser.jetstack.io-extra` | When the original identity carries extra info | A JSON-encoded map of arrays with all the original `extra` fields. |

> [!IMPORTANT]
> The `originaluser.jetstack.io-*` keys are a runtime API contract, left
> unchanged from upstream. When you use `Impersonate-Extra-` headers, the
> proxy's ServiceAccount must be explicitly authorized via RBAC to impersonate
> that extra key — extras are treated as subresources requiring explicit
> authorization.

## Token passthrough

Enable passthrough for tokens that fail OIDC authentication. The proxy then
performs a [TokenReview](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication)
against the target backend via the Kubernetes API; if it succeeds, the request
is forwarded as-is with the token intact and no other authentication applied.

```text
--token-passthrough
```

If the API server's authenticator is audience-aware, it validates the token's
audiences against the API server's own. To validate against a different set
instead, supply them — at least one must be present in the token:

```text
--token-passthrough-audiences=aud1.foo.bar,aud2.foo.bar
```

### TokenReview caching

Review results are cached per the `--token-passthrough-cache-success-ttl` and
`--token-passthrough-cache-failure-ttl` flags (both `10s` by default; errors
are never cached). Note that a cached success outlives token revocation for up
to the success TTL. The flow, key derivation, and tuning tradeoffs are
documented in [Caching and API-server protection](./caching.md#tokenreview-result-cache).

## No impersonation

Disable impersonation entirely: after a request authenticates, it is forwarded
as-is, with no header changes and no authentication injected by the proxy. The
OIDC bearer token stays in the request. Useful for fronting endpoints that
implement no authentication or authorization of their own.

```text
--disable-impersonation
```

## Extra impersonation headers

Add `Extra` info to the impersonated user — for example, to pass client or proxy
details to the target server. Two options are supported.

**Client IP** — append the remote client IP:

```text
--extra-user-header-client-ip
```

Proxied requests then carry `Impersonate-Extra-Remote-Client-Ip: <CLIENT_IP>`,
where `<CLIENT_IP>` is the [resolved client IP](./configuration.md#trusted-proxies-and-client-ip).
By default this is the direct peer address; `X-Forwarded-For` is only consulted
when the peer is a configured trusted proxy.

**Arbitrary headers** — comma-separated `key=value` pairs; a key may repeat to
carry multiple values:

```text
--extra-user-headers=key1=foo,key2=bar,key1=bar
```

Proxied requests then carry:

```text
Impersonate-Extra-Key1: foo,bar
Impersonate-Extra-Key2: bar
```

## Glossary

| Term | Meaning here |
| --- | --- |
| **Identity provider** | The system that authenticates people or workloads and mints tokens: GitHub Actions, Google, Dex, TeamCity. |
| **Issuer** | One `iss` URL the proxy trusts, with its discovery document and JWKS. An identity provider usually operates one issuer; the proxy is configured per issuer. |
| **Claim mapping** | The rule that turns a token's claims into a Kubernetes identity: a username, groups, optionally a UID and `extra` values. |
| **Mapped identity** | The result of that mapping: what the proxy impersonates and what RBAC bindings name. |
| **Username** | The single string identifying the mapped identity, prefix included, exactly as an RBAC `User` subject must spell it. |
| **Impersonation** | The proxy authenticating to the API server as its own ServiceAccount and asserting the mapped identity through `Impersonate-*` headers. Outbound impersonation is what the proxy always does; inbound impersonation is a client's own `kubectl --as`. |
| **Passthrough** | Forwarding a non-OIDC bearer token unchanged after a `TokenReview`, with no impersonation. |
| **Access record** | The `request.access.decided` log record the proxy writes for every request, with the mapped identity and its own admission decision. |
| **Audit event** | A Kubernetes audit event, written by the proxy's audit backend or by the API server; distinct from the log stream. |

## Common questions

**Do clients need a new kubeconfig?** Yes. The proxy is a different endpoint
from the API server, so a kubeconfig's `server` must point at it and its
`certificate-authority` must trust the proxy's serving certificate. The token
side is whatever mints the OIDC token: a credential plugin for people, a CI
system's token for pipelines. See
[point kubectl at the proxy](./getting-started.md#point-kubectl-at-the-proxy).

**Where is RBAC evaluated?** In the API server, for the mapped identity, on
every request. The proxy decides who a request is, never what it may do. The
one authorization the proxy performs itself is whether a caller may
impersonate someone else with `kubectl --as`, and it asks the API server that
too, through a `SubjectAccessReview`.

**Why can authentication succeed and the request still fail with 403?** Because
those are the two different decisions above. `AuSuccess` in the proxy's log
means the token was valid and the request was forwarded; a 403 after it means
RBAC has no binding for the mapped identity, or the proxy's own ServiceAccount
lacks an impersonation grant for something it sent. The
[troubleshooting table](./operations.md#troubleshooting) separates the two.

**Does changing the configuration restart the pods?** Changing
`authenticationConfig.content` or any value that renders as a flag changes
the pod spec, so `helm upgrade` rolls the Deployment. The proxy reads its
configuration once at startup; a file it mounts from a ConfigMap you manage
yourself, such as an audit policy, is not watched, so restart the pods after
editing one.

**Can one identity map to several groups?** Yes. A groups expression may
return a list, and that is the recommended way to give one token several
tiers of access; see the
[GitHub Actions recipe](./integrations.md#github-actions).

## See also

- [Integrations](./integrations.md) — recipes per identity provider.
- [Multi-issuer authentication](./multi-issuer.md) — the structured
  configuration format, readiness and security rules.
- [Configuration reference](./configuration.md) — every flag.
- [Caching and API-server protection](./caching.md) — the review caches this
  page mentions, with their consistency trade-offs.
