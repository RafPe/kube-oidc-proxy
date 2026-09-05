# Configuration reference

Every proxy flag, and the rules for resolving the client IP behind trusted
proxies. The Helm chart wires most flags from values; any of them can also be
passed directly via `extraArgs`. Flags are defined in
[`../cmd/app/options/`](../cmd/app/options/).

What the flags mean for identity, impersonation, passthrough and extra
headers is explained in [authentication and identity](./authentication.md);
the structured multi-issuer format has its own guide,
[multi-issuer authentication](./multi-issuer.md).

- [CLI reference](#cli-reference)
  - [Multi-issuer authentication](#multi-issuer-authentication)
  - [Single-issuer OIDC](#single-issuer-oidc)
  - [OIDC issuer mutual TLS](#oidc-issuer-mutual-tls)
  - [Token passthrough & impersonation](#token-passthrough--impersonation)
  - [Logging](#logging)
  - [Serving / TLS & misc](#serving--tls--misc)
- [Trusted proxies and client IP](#trusted-proxies-and-client-ip)
  - [Resolution rules](#resolution-rules)
  - [Default: trust nothing](#default-trust-nothing)
  - [Deployment topology](#deployment-topology)
- [Auditing](#auditing)
- [See also](#see-also)

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

Mutually exclusive with `--authentication-config`: the binary refuses to start
when both are given. The Helm chart never produces that combination, because
it does not render the issuer-specific `oidc.*` values while
`authenticationConfig.content` is set.

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
| `--token-passthrough-request-timeout` | `10s` | Timeout for each TokenReview request sent to the target API server when validating a passthrough token. |
| `--token-passthrough-cache-success-ttl` | `10s` | How long a successful TokenReview result is reused without a new API-server request. A cached success outlives token revocation for up to this duration, so keep it low. `0` disables caching successes. See [caching](./caching.md#tokenreview-result-cache). |
| `--token-passthrough-cache-failure-ttl` | `10s` | How long an unauthenticated TokenReview result is cached, shielding the API server from repeated reviews of the same invalid token. Review errors are never cached. `0` disables caching failures. |
| `--disable-impersonation` | `false` | (Alpha) Forward authenticated requests as-is, without impersonation. |
| `--extra-user-header-client-ip` | `false` | (Alpha) Add `Impersonate-Extra-Remote-Client-IP` with the request's resolved client IP. |
| `--extra-user-headers` | — | (Alpha) Extra `key=value` user headers to add to the impersonated request. |
| `--trusted-proxies` | — | Comma-separated trusted proxy CIDRs (IPv4/IPv6). `X-Forwarded-For` is honoured for client-IP resolution only when the immediate peer is within one of these networks. Empty (default) trusts no proxy. See [Trusted proxies and client IP](#trusted-proxies-and-client-ip). |
| `--subject-access-review-timeout` | `5s` | Timeout for authorizing inbound impersonation via `SubjectAccessReview` — a single shared budget across all SAR calls for one request (not per-call). Must be greater than 0. |
| `--subject-access-review-cache-allow-ttl` | `10s` | How long an **allowed** impersonation SAR decision is served from a bounded in-memory cache before being re-checked. Revoking an RBAC impersonation grant can take up to this long to be enforced. `0` disables caching of allows. See [caching](./caching.md#subjectaccessreview-decision-cache). |
| `--subject-access-review-cache-deny-ttl` | `10s` | How long a **denied** impersonation SAR decision is served from the cache. A newly granted RBAC impersonation permission can take up to this long to be honoured. `0` disables caching of denies. |
| `--max-impersonation-header-values` | `64` | Maximum total number of impersonation header values accepted per request. Each value costs one `SubjectAccessReview` round trip; over-cap requests are rejected with HTTP 431 before any review is sent. Must be greater than 0. See [caching](./caching.md#impersonation-header-value-cap). |
| `--allow-reserved-groups` | _(empty)_ | Comma-separated `system:`-prefixed groups a token may carry. See [Reserved `system:` identities](./authentication.md#reserved-system-identities). |

### Logging

| Flag | Default | Description |
| --- | --- | --- |
| `--logging-format` | `json` | Encoding of the whole log stream: `json` or `text`. Any other value is rejected at startup. |
| `-v` / `--v` | `0` | Verbosity, the single knob. `0` shows ERROR, WARN and INFO — lifecycle records and the per-request access record. `1` and above add DEBUG: the auth path taken, cache hits and misses, live `SubjectAccessReview`s, impersonation header names. WARN and ERROR are never hidden. |

There is no separate `--log-level`: `-v` drives the proxy's own records and the
bridged Kubernetes library output together, so the two can never disagree. Both
flags are rendered by the chart from `logging.format` and `logging.verbosity`
when those values are set, before `extraArgs`, so an `extraArgs` entry for the
same flag still wins. Both chart values are empty by default, so a default
install passes neither flag and the binary defaults above apply.

See the [logging reference](./logging.md) for the record shape, the event
registry, the level policy and worked queries.

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
dynamic configuration (`--audit-dynamic-configuration` is **not** supported).
The proxy stamps every request with an `Audit-ID` that is also the `request_id`
in its own log and the `auditID` in the kube-apiserver audit event, so the three
streams join.

[Auditing](./auditing.md) covers the rest: how the audit filters sit in the
request path, enabling a stdout audit log with the chart, policy examples, and
joining the proxy's events with the API server's audit log. For the proxy's own
per-request stdout log, see
[reading the request log](./operations.md#reading-the-request-log).

## See also

- [Multi-issuer authentication](./multi-issuer.md)
- [Getting started](./getting-started.md)
- [Caching and API-server protection](./caching.md)
- [Logging reference](./logging.md)
- [Architecture](./architecture.md)
- [Operations](./operations.md)
- [Chart values reference](../chart/kube-oidc-proxy/README.md)
