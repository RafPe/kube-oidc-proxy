# Usage

The proxy has two **mutually exclusive** authentication modes. Choose exactly
one:

| Mode | How to enable | Flags used |
| --- | --- | --- |
| **Single-issuer** | Set `oidc.clientId`, `oidc.issuerUrl`, `oidc.usernameClaim` | `--oidc-*` |
| **Multi-issuer** | Set `authenticationConfig.content` | `--authentication-config` |

> [!WARNING]
> When `authenticationConfig.content` is non-empty the chart passes
> `--authentication-config` and **omits every `--oidc-*` flag**; the `oidc.*`
> values are ignored. Don't configure both modes at once — the proxy rejects it
> (`authentication-config and --oidc-* flags are mutually exclusive`).

## Single-issuer configuration

```yaml
oidc:
  clientId: my-client
  issuerUrl: https://accounts.google.com
  usernameClaim: email
  groupsClaim: groups          # 👈 optional: claim carrying the user's groups
  requiredClaims:              # 👈 optional: claims that MUST match
    hd: example.com
```

If the issuer presents a certificate from a private CA, supply it inline so the
proxy can verify the TLS connection:

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

See the [CLI reference](./cli-reference.md) for the full list of single-issuer
`--oidc-*` knobs (prefixes, signing algorithms, required claims).

## Multi-issuer configuration

Accept tokens from several identity providers by supplying a Kubernetes
`AuthenticationConfiguration` under `authenticationConfig.content`. The proxy
builds one authenticator per issuer and combines them into a **union
authenticator** (see [architecture.md](./architecture.md)); an incoming token is
accepted by the first issuer that validates it.

Each issuer's CA (if any) must be inline under `issuer.certificateAuthority`.

```yaml
# All oidc.* fields are ignored while this is set.
readinessRequireAllIssuers: true   # 👈 wait for EVERY issuer before Ready (see note)
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
            prefix: "google:"       # 👈 prefix avoids username clashes across issuers
          groups:
            claim: groups
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

The `AuthenticationConfiguration` schema is the same one the API server accepts
(`apiserver.config.k8s.io/v1` or `v1beta1`). Each `jwt` entry describes one
issuer:

- **`issuer.url`** — the issuer's discovery URL.
- **`issuer.audiences`** — audiences a token must carry to be accepted.
- **`issuer.certificateAuthority`** — inline PEM CA, for issuers behind a
  private CA.
- **`claimMappings.username` / `.groups`** — which claim becomes the username /
  groups, plus an optional `prefix`. Distinct prefixes keep one issuer's `alice`
  from colliding with another's.

### Readiness semantics

> [!NOTE]
> `readinessRequireAllIssuers` controls readiness semantics only:
> - **`false` (default)** — the pod is Ready as soon as **at least one** issuer
>   initializes (JWKS fetched). A single IdP outage can't block a rollout for
>   every other system; still-pending issuers keep initializing in the
>   background.
> - **`true`** — the pod is Ready only once **every** issuer has initialized.
>
> Configuration errors always fail startup, regardless of this flag.

A complete, CI-tested multi-issuer example lives at
[`../chart/kube-oidc-proxy/ci/multi-issuer-values.yaml`](../chart/kube-oidc-proxy/ci/multi-issuer-values.yaml),
and the [multi-issuer task doc](./tasks/multi-issuer.md) walks through it end to
end. To try it on a local kind cluster against the real GitHub Actions issuer,
see the [kind + GitHub Actions walkthrough](./tasks/testing-kind-github-actions.md).

## See also

- [Impersonation model](./impersonation.md)
- [Token passthrough](./tasks/token-passthrough.md)
- [Extra impersonation headers](./tasks/extra-impersonation-headers.md)
- [CLI reference](./cli-reference.md)
- [Chart values reference](../chart/kube-oidc-proxy/README.md)
