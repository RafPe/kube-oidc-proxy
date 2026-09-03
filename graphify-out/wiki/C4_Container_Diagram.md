# C4 Container Diagram

> 5 nodes

## Key Concepts

- **kube-oidc-proxy (Container: Go) - reverse proxy validating OIDC tokens against the union of issuers and impersonating the mapped user to the API server** (4 connections) — `docs/c4/diagrams/structurizr-Containers.png`
- **OIDC issuer(s) / IdP (Software System) - Dex, Okta, GitHub Actions OIDC; issues ID tokens and publishes JWKS** (4 connections) — `docs/c4/diagrams/structurizr-Containers.png`
- **C4 Container View: kube-oidc-proxy (diagram)** (4 connections) — `docs/c4/diagrams/structurizr-Containers.png`
- **Kubernetes API server (Software System) - managed control plane running TokenReview, SubjectAccessReview and RBAC for the impersonated identity** (3 connections) — `docs/c4/diagrams/structurizr-Containers.png`
- **Platform user (Person) - runs kubectl carrying an OIDC ID token** (3 connections) — `docs/c4/diagrams/structurizr-Containers.png`

## Relationships

- No strong cross-community connections detected

## Source Files

- `docs/c4/diagrams/structurizr-Containers.png`

## Audit Trail

- EXTRACTED: 8 (89%)
- INFERRED: 1 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*