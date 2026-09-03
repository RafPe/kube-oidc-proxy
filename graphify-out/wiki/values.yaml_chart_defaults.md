# values.yaml (chart defaults)

> God node · 15 connections · `chart/kube-oidc-proxy/values.yaml`

**Community:** [Helm Chart Templates & CI Values](Helm_Chart_Templates_&_CI_Values.md)

## Connections by Relation

### references
- kube-oidc-proxy Helm chart README `EXTRACTED`
- values.authenticationConfig.content (multi-issuer) `EXTRACTED`
- values.readinessRequireAllIssuers `EXTRACTED`
- values.extraImpersonationHeaders (clientIP, headers) `EXTRACTED`
- values.oidc (single-issuer settings) `EXTRACTED`
- values.tokenPassthrough (enabled, audiences, cache TTLs) `EXTRACTED`
- values.maxImpersonationHeaderValues `EXTRACTED`
- values.securityContext (no privilege escalation, read-only rootfs, drop ALL) `EXTRACTED`
- values.subjectAccessReview (cacheAllowTTL/cacheDenyTTL) `EXTRACTED`
- values.extraArgs / extraVolumes / extraVolumeMounts `EXTRACTED`
- values.ingress `EXTRACTED`
- values.service (type, port 443, traffic policies) `EXTRACTED`
- values.podDisruptionBudget `EXTRACTED`
- values.podSecurityContext (runAsNonRoot, runAsUser 1000, RuntimeDefault seccomp) `EXTRACTED`
- values.tls (serving certificate: secretName / cert-manager / self-signed) `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*