# CLI reference

The proxy binary is `kube-oidc-proxy`. The Helm chart wires these flags from
values, but you can pass any of them directly (or via `extraArgs`). Flags are
defined in [`../cmd/app/options/`](../cmd/app/options/).

## Multi-issuer authentication

| Flag | Default | Description |
| --- | --- | --- |
| `--authentication-config` | — | Path to an `AuthenticationConfiguration` (`apiserver.config.k8s.io/v1` or `v1beta1`) enabling multi-issuer OIDC. Mutually exclusive with the `--oidc-*` flags. |
| `--readiness-require-all-issuers` | `false` | Report ready only once **every** issuer has initialized (JWKS fetched). Default: ready after the first issuer; others keep initializing in the background. |

## Single-issuer OIDC

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

## Token passthrough & impersonation

| Flag | Default | Description |
| --- | --- | --- |
| `--token-passthrough` | `false` | (Alpha) Bearer tokens that fail OIDC validation are tried via TokenReview and, if valid, forwarded as-is with no impersonation. |
| `--token-passthrough-audiences` | — | (Alpha) Allowed audiences for passthrough tokens. |
| `--disable-impersonation` | `false` | (Alpha) Forward authenticated requests as-is, without impersonation. |
| `--extra-user-header-client-ip` | `false` | (Alpha) Add `Impersonate-Extra-Remote-Client-IP` with the request's remote address. |
| `--extra-user-headers` | — | (Alpha) Extra `key=value` user headers to add to the impersonated request. |

## Serving / TLS & misc

| Flag | Default | Description |
| --- | --- | --- |
| `--secure-port` | `6443` | Port to serve HTTPS on. **The chart overrides this to `8443`** (readiness on `8080`, Service `443` → `8443`). |
| `--tls-cert-file` / `--tls-private-key-file` | — | Serving certificate and key. |
| `--bind-address` | `0.0.0.0` | Address to serve on. |
| `--readiness-probe-port` / `-P` | `8080` | Port exposing the `/ready` readiness probe. |
| `--flush-interval` | `50ms` | Interval to flush request bodies (streaming requests flush immediately). |
| `--kube-client-qps` / `--kube-client-burst` | — | Throttling for the proxy's own API-server client. |
| `--version` | — | Print version information and exit. |

## See also

- [Usage](./usage.md)
- [Multi-issuer OIDC authentication](./tasks/multi-issuer.md)
- [Token passthrough](./tasks/token-passthrough.md)
- [No impersonation](./tasks/no-impersonation.md)
- [Extra impersonation headers](./tasks/extra-impersonation-headers.md)
- [Auditing](./tasks/auditing.md)
