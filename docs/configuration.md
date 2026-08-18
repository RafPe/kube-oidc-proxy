# Configuration reference

All proxy flags, the impersonation model, and the optional task recipes. The
Helm chart wires most flags from values; you can also pass any of them directly
via `extraArgs`. Flags are defined in [`../cmd/app/options/`](../cmd/app/options/).

> **Multi-issuer is the headline feature.** Accepting tokens from several OIDC
> issuers at once has its own guide: [multi-issuer authentication](./multi-issuer.md).

## CLI reference

The proxy binary is `kube-oidc-proxy`. Its `--oidc-*` flags mirror the
Kubernetes API server's own OIDC authenticator, so single-issuer configuration
carries over one-to-one.

### Multi-issuer authentication

| Flag | Default | Description |
| --- | --- | --- |
| `--authentication-config` | — | Path to an `AuthenticationConfiguration` (`apiserver.config.k8s.io/v1` or `v1beta1`) enabling multi-issuer OIDC. Mutually exclusive with issuer-specific `--oidc-*` flags; the OIDC TLS client certificate/key flags may be shared by all issuers. |
| `--readiness-require-all-issuers` | `false` | Report ready only once **every** issuer has initialized (JWKS fetched). Default: ready after the first issuer; others keep initializing in the background. |

### Single-issuer OIDC

All ignored when `--authentication-config` is set.

| Flag | Default | Description |
| --- | --- | --- |
| `--oidc-issuer-url` | — | URL of the OpenID issuer (HTTPS only). |
| `--oidc-client-id` | — | Client ID expected in the token audience. |
| `--oidc-ca-file` | — | CA that verifies the issuer's TLS; falls back to the host root CAs. |
| `--oidc-username-claim` | `sub` | Token claim used as the username. |
| `--oidc-username-prefix` | — | Prefix prepended to usernames (`-` to disable prefixing). |
| `--oidc-groups-claim` | — | Token claim carrying the user's groups. |
| `--oidc-groups-prefix` | — | Prefix prepended to group names. |
| `--oidc-signing-algs` | `RS256` | Comma-separated allowed JOSE signing algorithms. |
| `--oidc-required-claim` | — | Repeatable `key=value` claim that must be present with a matching value. |

### OIDC issuer mutual TLS

These flags apply to every configured issuer in both single- and multi-issuer
modes. They must be supplied together.

| Flag | Default | Description |
| --- | --- | --- |
| `--oidc-tls-client-cert-file` | — | X.509 client certificate presented during issuer discovery and JWKS retrieval. |
| `--oidc-tls-client-key-file` | — | Private key matching the OIDC client certificate. |

File-backed OIDC client credentials are re-read by client-go. When the pair is
rotated, existing issuer connections are closed and subsequent discovery/JWKS
requests use the new certificate. The chart exposes this through
`oidc.tlsClient.existingSecret`; Kubernetes updates to the projected Secret do
not require a pod restart.

### Token passthrough & impersonation

| Flag | Default | Description |
| --- | --- | --- |
| `--token-passthrough` | `false` | (Alpha) Bearer tokens that fail OIDC validation are tried via TokenReview and, if valid, forwarded as-is with no impersonation. |
| `--token-passthrough-audiences` | — | (Alpha) Allowed audiences for passthrough tokens. |
| `--disable-impersonation` | `false` | (Alpha) Forward authenticated requests as-is, without impersonation. |
| `--extra-user-header-client-ip` | `false` | (Alpha) Add `Impersonate-Extra-Remote-Client-IP` with the request's resolved client IP. |
| `--extra-user-headers` | — | (Alpha) Extra `key=value` user headers to add to the impersonated request. |
| `--trusted-proxies` | — | Comma-separated trusted proxy CIDRs (IPv4/IPv6). `X-Forwarded-For` is honoured for client-IP resolution only when the immediate peer is within one of these networks. Empty (default) trusts no proxy. See [Trusted proxies and client IP](#trusted-proxies-and-client-ip). |
| `--subject-access-review-timeout` | `5s` | Timeout for authorizing inbound impersonation via `SubjectAccessReview` — a single shared budget across all SAR calls for one request (not per-call). Must be greater than 0. |
| `--allow-reserved-identity-claims` | `false` | Allow an authentication token to mint `system:`-prefixed identities. See [Reserved `system:` identities](#reserved-system-identities). |

### Serving / TLS & misc

| Flag | Default | Description |
| --- | --- | --- |
| `--secure-port` | `6443` | Port to serve HTTPS on. **The chart overrides this to `8443`** (readiness on `8080`, Service `443` → `8443`). |
| `--tls-cert-file` / `--tls-private-key-file` | — | Serving certificate and key. |
| `--bind-address` | `0.0.0.0` | Address to serve on. |
| `--readiness-probe-port` / `-P` | `8080` | Port exposing the `/ready` readiness probe. |
| `--flush-interval` | `50ms` | Interval to flush request bodies (streaming requests flush immediately). |
| `--kube-client-qps` / `--kube-client-burst` | — | Throttling for the proxy's own API-server client. |
| `--version` | — | Print version information and exit. |

## Impersonation model

`kube-oidc-proxy` forwards authenticated requests to the API server by
[impersonating](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)
the end user: it authenticates as its **own ServiceAccount** and attaches
`Impersonate-User` / `Impersonate-Group` / `Impersonate-Extra-*` headers for the
mapped identity. Impersonation **replaces, but does not bypass, RBAC** — the API
server still authorizes the impersonated identity.

### Inbound impersonation (`kubectl --as`)

The proxy also honours impersonation headers on **inbound** requests, so
`kubectl --as` works through it. When a request carries impersonation headers,
the proxy first checks — via `SubjectAccessReview` against the API server — that
the authenticated user may assume that identity, then forwards the impersonated
identity instead of the caller's own.

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

Set `--allow-reserved-identity-claims` to opt out and restore the previous
behaviour. It permits a token claim to mint `system:masters` and any service
account identity; only enable it if you fully control the issuer's claims.

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

```
--token-passthrough
```

If the API server's authenticator is audience-aware, it validates the token's
audiences against the API server's own. To validate against a different set
instead, supply them — at least one must be present in the token:

```
--token-passthrough-audiences=aud1.foo.bar,aud2.foo.bar
```

## No impersonation

Disable impersonation entirely: after a request authenticates, it is forwarded
as-is, with no header changes and no authentication injected by the proxy. The
OIDC bearer token stays in the request. Useful for fronting endpoints that
implement no authentication or authorization of their own.

```
--disable-impersonation
```

## Extra impersonation headers

Add `Extra` info to the impersonated user — for example, to pass client or proxy
details to the target server. Two options are supported.

**Client IP** — append the remote client IP:

```
--extra-user-header-client-ip
```

Proxied requests then carry `Impersonate-Extra-Remote-Client-Ip: <CLIENT_IP>`,
where `<CLIENT_IP>` is the [resolved client IP](#trusted-proxies-and-client-ip).
By default this is the direct peer address; `X-Forwarded-For` is only consulted
when the peer is a configured trusted proxy.

**Arbitrary headers** — comma-separated `key=value` pairs; a key may repeat to
carry multiple values:

```
--extra-user-headers=key1=foo,key2=bar,key1=bar
```

Proxied requests then carry:

```
Impersonate-Extra-Key1: foo,bar
Impersonate-Extra-Key2: foo
```

## Trusted proxies and client IP

The proxy resolves a single **client IP** per request and uses it consistently
for both the per-request access log (`src_ip`) and, when
`--extra-user-header-client-ip` is set, the `Impersonate-Extra-Remote-Client-IP`
header forwarded to the API server.

### Resolution rules

- The **direct peer** (`RemoteAddr`, the TCP source of the connection) is always
  authoritative.
- `X-Forwarded-For` is honoured **only when the immediate peer's address falls
  within a configured `--trusted-proxies` CIDR**. The chain is then walked from
  the hop nearest the proxy toward the origin, trusted hops are skipped, and the
  first untrusted address is taken as the client.
- If the peer is not trusted, if no proxies are configured, or if a forwarded
  entry is malformed, the direct peer is used.
- Only `X-Forwarded-For` is parsed. The RFC 7239 `Forwarded` header is **not**
  honoured.

### Default: trust nothing

`--trusted-proxies` defaults to empty. With no trusted proxies configured, the
proxy **never** trusts `X-Forwarded-For` and always uses the direct peer as the
client IP. This is the safe default.

> [!WARNING]
> `X-Forwarded-For` is a client-supplied header. If the proxy honoured it
> unconditionally, any client connecting directly could forge its own client IP —
> poisoning audit logs and the `Remote-Client-IP` impersonation extra. Configure
> `--trusted-proxies` **only** with the addresses of load balancers or reverse
> proxies you operate directly in front of `kube-oidc-proxy`. Never include
> untrusted or client-reachable networks.

### Deployment topology

- **No proxy in front** (clients reach the proxy directly): leave
  `--trusted-proxies` empty. The direct peer is the client.
- **Behind a load balancer / ingress that sets `X-Forwarded-For`**: set
  `--trusted-proxies` to the CIDR(s) the proxy sees those hops arriving from
  (for example the pod/Service network or the LB's egress range), so the real
  client IP is recovered from the forwarded chain. Example:

  ```
  --trusted-proxies=10.0.0.0/8,192.168.0.0/16,fd00::/8
  ```

## Auditing

The proxy exposes the same auditing options as the Kubernetes API server, except
dynamic configuration (`--audit-dynamic-configuration` is **not** supported). See
the [Kubernetes auditing docs](https://kubernetes.io/docs/tasks/debug-application-cluster/audit)
to configure it. For the proxy's own per-request stdout log, see
[reading the request log](./operations.md#reading-the-request-log).

## See also

- [Multi-issuer authentication](./multi-issuer.md)
- [Getting started](./getting-started.md)
- [Architecture](./architecture.md)
- [Operations](./operations.md)
- [Chart values reference](../chart/kube-oidc-proxy/README.md)
