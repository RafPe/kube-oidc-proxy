# Changelog: Audit & Readiness

> 9 nodes

## Key Concepts

- **Release 1.3.0 (2026-08-19)** (7 connections) — `CHANGELOG.md`
- **Multi-issuer OIDC authentication** (6 connections) — `README.md`
- **Configurable readiness (first issuer vs all issuers)** (4 connections) — `README.md`
- **Deployment readiness probe (GET /ready on 8080)** (3 connections) — `chart/kube-oidc-proxy/templates/deployment.yaml`
- **Readiness reports not-ready until the proxy is serving** (3 connections) — `CHANGELOG.md`
- **Core API group (/api) audit RequestInfo classification fix** (2 connections) — `CHANGELOG.md`
- **Audit streaming requests as long-running (ResponseStarted)** (2 connections) — `CHANGELOG.md`
- **OIDC token validation failures logged at -v=2 with remote address** (1 connections) — `CHANGELOG.md`
- **Union authenticator** (1 connections) — `README.md`

## Relationships

- [Helm Chart Templates & CI Values](Helm_Chart_Templates_&_CI_Values.md) (4 shared connections)
- [Changelog: Caching & Reserved Identity](Changelog-_Caching_&_Reserved_Identity.md) (2 shared connections)
- [Chart Metadata & Project Overview](Chart_Metadata_&_Project_Overview.md) (1 shared connections)

## Source Files

- `CHANGELOG.md`
- `README.md`
- `chart/kube-oidc-proxy/templates/deployment.yaml`

## Audit Trail

- EXTRACTED: 13 (72%)
- INFERRED: 5 (28%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*