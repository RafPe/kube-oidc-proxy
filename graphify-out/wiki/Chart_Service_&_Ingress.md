# Chart Service & Ingress

> 6 nodes

## Key Concepts

- **NOTES.txt (post-install notes)** (5 connections) — `chart/kube-oidc-proxy/templates/NOTES.txt`
- **Service template (https port -> 8443)** (3 connections) — `chart/kube-oidc-proxy/templates/service.yaml`
- **values.ingress** (3 connections) — `chart/kube-oidc-proxy/values.yaml`
- **values.service (type, port 443, traffic policies)** (3 connections) — `chart/kube-oidc-proxy/values.yaml`
- **Ingress template** (2 connections) — `chart/kube-oidc-proxy/templates/ingress.yaml`
- **Helm test pod (wget connection test)** (1 connections) — `chart/kube-oidc-proxy/templates/tests/test-connection.yaml`

## Relationships

- [Helm Chart Templates & CI Values](Helm_Chart_Templates_&_CI_Values.md) (5 shared connections)

## Source Files

- `chart/kube-oidc-proxy/templates/NOTES.txt`
- `chart/kube-oidc-proxy/templates/ingress.yaml`
- `chart/kube-oidc-proxy/templates/service.yaml`
- `chart/kube-oidc-proxy/templates/tests/test-connection.yaml`
- `chart/kube-oidc-proxy/values.yaml`

## Audit Trail

- EXTRACTED: 10 (91%)
- INFERRED: 1 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*