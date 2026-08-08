# Architecture

`kube-oidc-proxy` is a reverse proxy that sits in front of a Kubernetes API
server. It authenticates the bearer token on each request against one or more
OIDC issuers, then forwards the request to the API server using
[impersonation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)
headers derived from the token's claims. The API server sees the request as the
mapped user; RBAC is evaluated for that user as usual.

Because the proxy performs authentication itself, you get OIDC login **without
touching the API server's `--oidc-*` flags** — exactly the knobs you can't reach
on a managed control plane (EKS, GKE, AKS, ...).

## Request flow

1. A client (`kubectl`) sends a request over HTTPS, carrying an OIDC **ID
   token** as a bearer token.
2. The proxy validates the JWT against the configured issuer(s): it fetches and
   caches each issuer's JWKS, then verifies the signature, issuer, audience,
   expiry, and any required claims.
3. On success, the proxy maps the token's claims to a Kubernetes identity —
   username, groups, and extra info — applying any configured prefixes.
4. The proxy forwards the original request to the **kube-apiserver**,
   authenticating with its **own ServiceAccount** and attaching
   `Impersonate-User` / `Impersonate-Group` / `Impersonate-Extra-*` headers for
   the mapped identity.
5. The API server evaluates **RBAC** for the impersonated identity and returns
   the response, which the proxy passes back to the client.

```mermaid
sequenceDiagram
    autonumber
    participant U as kubectl (user)
    participant P as kube-oidc-proxy
    participant J as OIDC issuer (JWKS)
    participant A as kube-apiserver
    participant R as RBAC

    U->>P: HTTPS request + Bearer ID token
    P->>J: Fetch JWKS / discovery (cached)
    J-->>P: Signing keys
    P->>P: Validate JWT<br/>(issuer, audience, signature, claims)
    Note over P: Map claims → username, groups, extra
    P->>A: Forward request as proxy ServiceAccount<br/>+ Impersonate-User / -Group / -Extra headers
    A->>R: Authorize impersonated identity
    R-->>A: Allow / Deny
    A-->>P: API response
    P-->>U: API response
```

## The auth → impersonate handler chain

Every request passes through the same pipeline:

1. **Authenticate.** The bearer token is validated. If it fails OIDC validation
   and token passthrough is enabled, the proxy falls back to a `TokenReview`
   against the API server (see [token passthrough](./configuration.md#token-passthrough)).
2. **Resolve the impersonation target.** If the inbound request also carries
   `Impersonate-*` headers (`kubectl --as`), the proxy runs a
   `SubjectAccessReview` to confirm the authenticated user may assume that
   identity before honouring it. See [the impersonation model](./configuration.md#impersonation-model).
3. **Impersonate.** The proxy rewrites the request to authenticate as its own
   ServiceAccount, attaches the impersonation headers for the resolved identity,
   and records the original caller in `originaluser.jetstack.io-*` extra headers
   for the API server's audit log.
4. **Proxy.** The request is streamed to the API server and the response streamed
   back.

## Multi-issuer union authenticator

Single-issuer mode uses the familiar `--oidc-*` flags and trusts exactly one
issuer. Multi-issuer mode (`--authentication-config`) loads a Kubernetes
[`AuthenticationConfiguration`](./multi-issuer.md) that lists several JWT
issuers, each with its own audiences and claim mappings.

The proxy builds one authenticator per issuer and combines them into a **union
authenticator**: an incoming token is offered to each issuer's authenticator in
turn, and the first one that accepts it wins. This is what lets a single proxy
accept, for example, tokens from your corporate IdP **and** from GitHub Actions'
OIDC issuer at the same time. Per-issuer username/group **prefixes** keep
identities from different issuers from colliding.

The two modes are **mutually exclusive**. When `--authentication-config` is set,
every `--oidc-*` flag is rejected (`authentication-config and --oidc-* flags are
mutually exclusive`).

## Readiness semantics

In multi-issuer mode, each issuer must fetch its JWKS before it can validate
tokens. The `--readiness-require-all-issuers` flag
(`readinessRequireAllIssuers` in the chart) controls how readiness relates to
that initialization:

- **`false` (default)** — the pod is Ready as soon as **at least one** issuer
  initializes. A single IdP outage can't block a rollout for every other system;
  still-pending issuers keep initializing in the background.
- **`true`** — the pod is Ready only once **every** issuer has initialized.

Configuration errors always fail startup, regardless of this flag.

## Diagrams

These [C4 model](https://c4model.com/) views zoom in from the system in its
environment down to the request-handling components. For the runtime view of a
single request, see [Request flow](#request-flow) above.

### System context (C4 level 1)

Who talks to the proxy and what it depends on: the user's `kubectl` presents an
ID token, the proxy verifies it against the external OIDC issuer(s), and then
impersonates the mapped user to the external Kubernetes API server.

```mermaid
C4Context
    title System context — kube-oidc-proxy

    Person(user, "Platform user", "Runs kubectl, carrying an OIDC ID token")
    System(proxy, "kube-oidc-proxy", "Authenticates the bearer token and impersonates the mapped user to the API server")
    System_Ext(idp, "OIDC issuer(s) / IdP", "Dex, Okta, GitHub Actions OIDC, ... issues ID tokens and publishes JWKS")
    System_Ext(apiserver, "Kubernetes API server", "Managed control plane; evaluates RBAC for the impersonated identity")

    Rel(user, idp, "Logs in, obtains ID token", "OIDC")
    Rel(user, proxy, "Sends request with bearer ID token", "HTTPS")
    Rel(proxy, idp, "Fetches discovery and JWKS to verify tokens", "HTTPS")
    Rel(proxy, apiserver, "Forwards request, impersonating the mapped user", "HTTPS")
    Rel(apiserver, user, "Returns API response via the proxy")
```

### Containers (C4 level 2)

Inside the proxy: TLS is terminated by the serving layer, which drives the
handler chain. The authenticator validates the token against the union of
issuers; a token-passthrough fallback and the inbound-`--as` check both consult
the API server, and the readiness probe watches each issuer's JWKS
initialization through the authenticator.

```mermaid
C4Container
    title Containers — kube-oidc-proxy

    Person(user, "Platform user", "Runs kubectl with an OIDC ID token")
    System_Ext(idp, "OIDC issuer(s) / IdP", "Issues ID tokens and publishes JWKS")
    System_Ext(apiserver, "Kubernetes API server", "TokenReview, SubjectAccessReview and RBAC; the impersonation target")

    System_Boundary(proxy_sys, "kube-oidc-proxy") {
        Container(serving, "HTTPS serving layer", "Go, SecureServingInfo", "Terminates TLS and runs the handler chain")
        Container(authn, "Authenticator", "Go, bearertoken + OIDC union", "Validates the bearer token against N issuers")
        Container(tokenreview, "Token passthrough", "Go, TokenReview client", "Fallback for tokens OIDC does not accept")
        Container(impersonate, "Impersonation handler", "Go, SubjectAccessReview client", "Builds the impersonation config and authorizes inbound --as")
        Container(audit, "Audit backend", "Go, k8s audit", "Records authenticated and unauthenticated requests")
        Container(probe, "Readiness probe", "Go, healthcheck", "Reports Ready once issuer JWKS are initialized")
    }

    Rel(user, serving, "Request with bearer ID token", "HTTPS")
    Rel(serving, authn, "1. Authenticate token")
    Rel(authn, idp, "Fetch and cache JWKS", "HTTPS")
    Rel(authn, tokenreview, "On OIDC failure, fall back")
    Rel(tokenreview, apiserver, "TokenReview, then forward caller token unchanged", "HTTPS")
    Rel(authn, impersonate, "2. On success, resolve identity")
    Rel(impersonate, apiserver, "SubjectAccessReview for inbound --as", "HTTPS")
    Rel(impersonate, apiserver, "3. Forward with Impersonate- headers", "HTTPS")
    Rel(impersonate, audit, "4. Emit audit events")
    Rel(probe, authn, "Probe JWKS init with a fake JWT")
```

### Handler-chain components (C4 level 3)

A structural view of the serving layer's handler chain, wrapped in execution
order authenticate then impersonate then audit then reverse proxy. Each stage
maps to a handler in `pkg/proxy`.

```mermaid
C4Component
    title Components — request handler chain

    System_Ext(idp, "OIDC issuer(s) / IdP", "JWKS")
    System_Ext(apiserver, "Kubernetes API server", "TokenReview, SubjectAccessReview, RBAC")

    Container_Boundary(chain, "Handler chain") {
        Component(authn_c, "withAuthenticateRequest", "bearertoken + OIDC union", "Validates the JWT; on failure tries TokenReview")
        Component(impersonate_c, "withImpersonateRequest", "Go", "Resolves the target and builds the impersonation config")
        Component(audit_c, "auditor.WithRequest", "k8s audit", "Records the request outcome")
        Component(rt_c, "RoundTrip", "ImpersonatingRoundTripper", "Attaches headers and streams the request upstream")
    }

    Rel(authn_c, idp, "Verify signature against JWKS", "HTTPS")
    Rel(authn_c, apiserver, "TokenReview fallback", "HTTPS")
    Rel(authn_c, impersonate_c, "On success, pass user info")
    Rel(impersonate_c, apiserver, "SubjectAccessReview for inbound --as", "HTTPS")
    Rel(impersonate_c, audit_c, "Continue chain")
    Rel(audit_c, rt_c, "Forward request")
    Rel(rt_c, apiserver, "Impersonated request", "HTTPS")
```

## See also

- [Multi-issuer authentication](./multi-issuer.md)
- [Getting started](./getting-started.md)
- [Configuration reference](./configuration.md)
- [Operations: security](./operations.md#security)
