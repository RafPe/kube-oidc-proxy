# Changelog: Caching & Reserved Identity

> 13 nodes

## Key Concepts

- **TokenReview result cache (success/failure TTLs)** (5 connections) — `CHANGELOG.md`
- **SubjectAccessReview (impersonation authorization)** (5 connections) — `README.md`
- **SubjectAccessReview decision cache (allow/deny TTLs)** (4 connections) — `CHANGELOG.md`
- **values.tokenPassthrough (enabled, audiences, cache TTLs)** (4 connections) — `chart/kube-oidc-proxy/values.yaml`
- **Token passthrough** (4 connections) — `README.md`
- **CHANGELOG** (4 connections) — `CHANGELOG.md`
- **Release 1.6.0 (2026-09-01)** (4 connections) — `CHANGELOG.md`
- **--max-impersonation-header-values cap (HTTP 431)** (3 connections) — `CHANGELOG.md`
- **values.subjectAccessReview (cacheAllowTTL/cacheDenyTTL)** (3 connections) — `chart/kube-oidc-proxy/values.yaml`
- **TokenReview (passthrough token validation)** (3 connections) — `README.md`
- **Reserved system: identity guard** (3 connections) — `CHANGELOG.md`
- **--allow-reserved-groups (replaces --allow-reserved-identity-claims)** (2 connections) — `CHANGELOG.md`
- **Release 1.4.0 (2026-08-20)** (2 connections) — `CHANGELOG.md`

## Relationships

- [Helm Chart Templates & CI Values](Helm_Chart_Templates_&_CI_Values.md) (5 shared connections)
- [Contributing, Maintaining & Fork Model](Contributing,_Maintaining_&_Fork_Model.md) (2 shared connections)
- [Changelog: Passthrough & Trusted Proxies](Changelog-_Passthrough_&_Trusted_Proxies.md) (2 shared connections)
- [Changelog: Audit & Readiness](Changelog-_Audit_&_Readiness.md) (2 shared connections)
- [Chart Metadata & Project Overview](Chart_Metadata_&_Project_Overview.md) (1 shared connections)

## Source Files

- `CHANGELOG.md`
- `README.md`
- `chart/kube-oidc-proxy/values.yaml`

## Audit Trail

- EXTRACTED: 27 (93%)
- INFERRED: 2 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*