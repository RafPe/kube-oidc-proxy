# Helm Chart Templates & CI Values

> 25 nodes

## Key Concepts

- **values.yaml (chart defaults)** (15 connections) — `chart/kube-oidc-proxy/values.yaml`
- **Deployment args: --authentication-config vs --oidc-* switch** (11 connections) — `chart/kube-oidc-proxy/templates/deployment.yaml`
- **Deployment template** (8 connections) — `chart/kube-oidc-proxy/templates/deployment.yaml`
- **kube-oidc-proxy Helm chart README** (8 connections) — `chart/kube-oidc-proxy/README.md`
- **values.authenticationConfig.content (multi-issuer)** (6 connections) — `chart/kube-oidc-proxy/values.yaml`
- **CI fixture: multi-issuer values** (6 connections) — `chart/kube-oidc-proxy/ci/multi-issuer-values.yaml`
- **values.extraImpersonationHeaders (clientIP, headers)** (5 connections) — `chart/kube-oidc-proxy/values.yaml`
- **values.oidc (single-issuer settings)** (5 connections) — `chart/kube-oidc-proxy/values.yaml`
- **values.readinessRequireAllIssuers** (5 connections) — `chart/kube-oidc-proxy/values.yaml`
- **Mutually exclusive single-issuer / multi-issuer chart modes** (5 connections) — `chart/kube-oidc-proxy/README.md`
- **Deployment volumes (config Secret, TLS Secret, client-TLS Secret)** (4 connections) — `chart/kube-oidc-proxy/templates/deployment.yaml`
- **values.maxImpersonationHeaderValues** (4 connections) — `chart/kube-oidc-proxy/values.yaml`
- **values.oidc.tlsClient (issuer mTLS credentials)** (4 connections) — `chart/kube-oidc-proxy/values.yaml`
- **values.securityContext (no privilege escalation, read-only rootfs, drop ALL)** (4 connections) — `chart/kube-oidc-proxy/values.yaml`
- **Hardened SecurityContext by default** (4 connections) — `chart/kube-oidc-proxy/README.md`
- **High-availability guidance (PDB + topology spread)** (3 connections) — `chart/kube-oidc-proxy/README.md`
- **values.extraArgs / extraVolumes / extraVolumeMounts** (3 connections) — `chart/kube-oidc-proxy/values.yaml`
- **values.podDisruptionBudget** (3 connections) — `chart/kube-oidc-proxy/values.yaml`
- **values.podSecurityContext (runAsNonRoot, runAsUser 1000, RuntimeDefault seccomp)** (3 connections) — `chart/kube-oidc-proxy/values.yaml`
- **CI fixture: single-issuer values** (3 connections) — `chart/kube-oidc-proxy/ci/single-issuer-values.yaml`
- **ClusterRoleBinding template** (2 connections) — `chart/kube-oidc-proxy/templates/clusterrolebinding.yaml`
- **PodDisruptionBudget template** (2 connections) — `chart/kube-oidc-proxy/templates/poddisruptionbudget.yaml`
- **values.tls (serving certificate: secretName / cert-manager / self-signed)** (2 connections) — `chart/kube-oidc-proxy/values.yaml`
- **Kubernetes AuthenticationConfiguration (apiserver.config.k8s.io)** (2 connections) — `README.md`
- **checksum/config pod annotation (secret_config.yaml)** (1 connections) — `chart/kube-oidc-proxy/templates/deployment.yaml`

## Relationships

- [Changelog: Caching & Reserved Identity](Changelog-_Caching_&_Reserved_Identity.md) (5 shared connections)
- [Chart Service & Ingress](Chart_Service_&_Ingress.md) (5 shared connections)
- [Changelog: Audit & Readiness](Changelog-_Audit_&_Readiness.md) (4 shared connections)
- [Chart Metadata & Project Overview](Chart_Metadata_&_Project_Overview.md) (3 shared connections)
- [Contributing, Maintaining & Fork Model](Contributing,_Maintaining_&_Fork_Model.md) (2 shared connections)
- [Changelog: Passthrough & Trusted Proxies](Changelog-_Passthrough_&_Trusted_Proxies.md) (1 shared connections)

## Source Files

- `README.md`
- `chart/kube-oidc-proxy/README.md`
- `chart/kube-oidc-proxy/ci/multi-issuer-values.yaml`
- `chart/kube-oidc-proxy/ci/single-issuer-values.yaml`
- `chart/kube-oidc-proxy/templates/clusterrolebinding.yaml`
- `chart/kube-oidc-proxy/templates/deployment.yaml`
- `chart/kube-oidc-proxy/templates/poddisruptionbudget.yaml`
- `chart/kube-oidc-proxy/values.yaml`

## Audit Trail

- EXTRACTED: 59 (86%)
- INFERRED: 10 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*