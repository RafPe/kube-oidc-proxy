# C4 Component Diagram

> 12 nodes

## Key Concepts

- **kube-oidc-proxy (Container boundary)** (8 connections) — `docs/c4/diagrams/structurizr-Components.png`
- **Authenticator (Go, bearertoken + OIDC union) - validates bearer token against union of N OIDC issuers** (6 connections) — `docs/c4/diagrams/structurizr-Components.png`
- **Impersonation handler (Go) - builds impersonation config and forwards the request** (5 connections) — `docs/c4/diagrams/structurizr-Components.png`
- **Kubernetes API server (Software System) - managed control plane running TokenReview, SubjectAccessReview and RBAC for the impersonated identity** (4 connections) — `docs/c4/diagrams/structurizr-Components.png`
- **Token passthrough (Go, TokenReview) - fallback for non-OIDC tokens validated via TokenReview with bounded cache** (4 connections) — `docs/c4/diagrams/structurizr-Components.png`
- **C4 Component Diagram: kube-oidc-proxy request-handling components** (4 connections) — `docs/c4/diagrams/structurizr-Components.png`
- **Audit backend (Go, k8s audit) - records authenticated and unauthenticated requests** (3 connections) — `docs/c4/diagrams/structurizr-Components.png`
- **OIDC issuer(s) / IdP (Software System) - Dex, Okta, GitHub Actions OIDC; issues ID tokens and publishes JWKS** (3 connections) — `docs/c4/diagrams/structurizr-Components.png`
- **Platform user (Person) - runs kubectl carrying an OIDC ID token** (3 connections) — `docs/c4/diagrams/structurizr-Components.png`
- **Secure serving layer (Go, SecureServingInfo) - terminates TLS and drives the handler chain** (3 connections) — `docs/c4/diagrams/structurizr-Components.png`
- **SubjectAccessReview client (Go, SubjectAccessReview) - authorizes inbound impersonation (kubectl --as), caps header values (431 over cap), split allow/deny TTL cache** (3 connections) — `docs/c4/diagrams/structurizr-Components.png`
- **Readiness probe (Go, healthcheck) - reports Ready once each issuer's JWKS is initialized** (2 connections) — `docs/c4/diagrams/structurizr-Components.png`

## Relationships

- No strong cross-community connections detected

## Source Files

- `docs/c4/diagrams/structurizr-Components.png`

## Audit Trail

- EXTRACTED: 23 (96%)
- INFERRED: 1 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*