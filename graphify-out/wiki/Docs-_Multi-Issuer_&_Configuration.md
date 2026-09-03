# Docs: Multi-Issuer & Configuration

> 67 nodes

## Key Concepts

- **Auth -> impersonate -> audit -> proxy handler chain** (11 connections) — `docs/architecture.md`
- **Configuration reference** (11 connections) — `docs/configuration.md`
- **Troubleshooting table** (10 connections) — `docs/operations.md`
- **Architecture doc** (10 connections) — `docs/architecture.md`
- **Operations doc** (10 connections) — `docs/operations.md`
- **SubjectAccessReview decision cache** (10 connections) — `docs/caching.md`
- **Structured AuthenticationConfiguration (apiserver.config.k8s.io v1/v1beta1)** (9 connections) — `docs/multi-issuer.md`
- **Security guidance (privileged component)** (9 connections) — `docs/operations.md`
- **Multi-Issuer OIDC Authentication guide** (9 connections) — `docs/multi-issuer.md`
- **TokenReview result cache** (9 connections) — `docs/caching.md`
- **Multi-issuer demo flow (two Dex issuers, one proxy)** (8 connections) — `demo/README.md`
- **--authentication-config flag** (8 connections) — `docs/configuration.md`
- **Impersonation model** (8 connections) — `docs/configuration.md`
- **Caching and API-server protection** (8 connections) — `docs/caching.md`
- **Getting started** (8 connections) — `docs/getting-started.md`
- **Multi-issuer union authenticator** (8 connections) — `docs/architecture.md`
- **Reserved system: identity refusal** (8 connections) — `docs/configuration.md`
- **Distinct per-issuer prefixes** (8 connections) — `docs/multi-issuer.md`
- **Inbound impersonation (kubectl --as)** (7 connections) — `docs/configuration.md`
- **Local multi-issuer test: kind and GitHub Actions token** (7 connections) — `docs/operations.md`
- **demo/run.sh orchestration** (7 connections) — `demo/README.md`
- **--readiness-require-all-issuers readiness semantics** (7 connections) — `docs/architecture.md`
- **CEL claim mappings (username/groups expressions)** (6 connections) — `docs/multi-issuer.md`
- **make e2e hermetic end-to-end suite** (6 connections) — `docs/operations.md`
- **Demo RBAC ClusterRoleBindings** (6 connections) — `demo/manifests/rbac.yaml`
- *... and 42 more nodes in this community*

## Relationships

- [Artifact Hub & Release Docs](Artifact_Hub_&_Release_Docs.md) (4 shared connections)

## Source Files

- `demo/README.md`
- `demo/manifests/proxy-values.yaml`
- `demo/manifests/rbac.yaml`
- `docs/architecture.md`
- `docs/caching.md`
- `docs/configuration.md`
- `docs/getting-started.md`
- `docs/multi-issuer.md`
- `docs/operations.md`

## Audit Trail

- EXTRACTED: 147 (91%)
- INFERRED: 15 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*