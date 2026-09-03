# C4 System Context Diagram

> 5 nodes

## Key Concepts

- **kube-oidc-proxy (Software System) - authenticates the bearer token and impersonates the mapped user to the API server** (4 connections) — `docs/c4/diagrams/structurizr-SystemContext.png`
- **System Context View: kube-oidc-proxy (C4 diagram)** (4 connections) — `docs/c4/diagrams/structurizr-SystemContext.png`
- **OIDC issuer(s) / IdP (Software System) - Dex, Okta, GitHub Actions OIDC; issues ID tokens and publishes JWKS** (3 connections) — `docs/c4/diagrams/structurizr-SystemContext.png`
- **Platform user (Person) - runs kubectl carrying an OIDC ID token** (3 connections) — `docs/c4/diagrams/structurizr-SystemContext.png`
- **Kubernetes API server (Software System) - managed control plane; runs TokenReview, SubjectAccessReview and RBAC for the impersonated identity** (2 connections) — `docs/c4/diagrams/structurizr-SystemContext.png`

## Relationships

- No strong cross-community connections detected

## Source Files

- `docs/c4/diagrams/structurizr-SystemContext.png`

## Audit Trail

- EXTRACTED: 7 (88%)
- INFERRED: 1 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*