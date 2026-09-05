# Unreleased
<!-- next-release -->

## [1.7.0] - 2026-09-05

- Security denials now appear at the default verbosity as `AuFail` records with a `reason`; the readiness transition is INFO; "issuers pending" is logged on change only; Kubernetes library output is JSON under `component=k8s`.
- Operational log messages changed value. The access record's `msg` was `proxied request` or `rejected request` and is now `access decision` for both, with the outcome in the frozen `event` field (`AuSuccess`/`AuFail`); other records carry new `msg` text as well. Queries and alerts must key on `event_type` (and `event` for the access record), not on `msg`, which is descriptive and not part of the contract.
- The access log no longer emits the original user's full extra-claims map under `outbound_extra`, and configured impersonation header values are no longer logged at any verbosity.
- One JSON log stream with a per-request `request_id` (also sent upstream as `Audit-ID`), a closed `event_type` registry documented in docs/logging.md, and `--logging-format`.

## [1.6.1] - 2026-09-04

- Helm chart now deploys the image matching its appVersion by default. Charts 1.2.0 through 1.6.0 shipped with a hardcoded `image.tag` of 1.1.0, so installs without an explicit `image.tag` override ran the 1.1.0 binary; the release pipeline now refuses to publish a chart whose default image tag differs from the release version.

## [1.6.0] - 2026-09-01

- Bump github.com/google/cel-go to v0.30.0 and go.etcd.io/etcd/{api,client/pkg,client}/v3 to v3.7.1 to remediate GO-2026-6094 and GO-2026-6107.
- Impersonation requests are now capped at a configurable number of Impersonate-* header values (--max-impersonation-header-values, default 64). Requests exceeding the cap are rejected with HTTP 431 before any SubjectAccessReview is sent, bounding the per-request authorization load a client can generate.
- Impersonation SubjectAccessReview decisions are now served from a bounded in-memory cache with separately configurable TTLs (--subject-access-review-cache-allow-ttl and --subject-access-review-cache-deny-ttl, default 10s, 0 disables). Revoking or granting an RBAC impersonation permission can take up to the corresponding TTL to be enforced through the proxy.
- Token passthrough now caches TokenReview results in a bounded in-memory cache with separately configurable TTLs (--token-passthrough-cache-success-ttl and --token-passthrough-cache-failure-ttl, default 10s, 0 disables). A revoked token can continue to pass for up to the success TTL and a newly valid token can be rejected for up to the failure TTL.

## [1.5.0] - 2026-08-28

- Audit event sourceIPs now follow the trusted-proxy contract — forwarded headers from untrusted peers are stripped before auditing and before the request is forwarded upstream, so clients can no longer spoof the audit trail via X-Forwarded-For. Operators with a load balancer in front of the proxy must set --trusted-proxies to resolve the real client IP.
- Unauthenticated (401) requests now produce audit events — the unauthorized audit chain initialises the audit context, so failed authentication attempts are recorded with a ResponseStarted event instead of leaving no trace in the audit log.
- Update k8s.io modules to v0.37.0, sigs.k8s.io/kind to v0.33.0, and test dependencies; refresh the distroless base image digest and move test tool images to alpine 3.24; bump all pinned GitHub Actions to current releases.
- Pull request e2e runs now exercise the full supported Kubernetes window (currently 1.37.0, 1.36.4, 1.35.8) instead of only the newest minor; the release path stays newest-only since the same code already passed the full window on its pull request.
- Test and CI tooling now targets Kubernetes 1.37 — the e2e suite boots kindest/node v1.37.0 by default, the kind CLI in the e2e workflows moves to v0.33.0 (kubeadm v1beta4 support, required since 1.37 dropped v1beta3), and the Makefile kubectl download fallback moves to v1.37.0.
- UID impersonation works end to end — an authorized Impersonate-Uid header is forwarded to the API server, the impersonation check reviews uids in the authentication.k8s.io group, and the chart grants the proxy impersonate on uids and on the originaluser.jetstack.io-uid extra. Deployments that map a uid claim now emit Impersonate-Uid and need the new RBAC.
- New --token-passthrough-request-timeout flag bounds each TokenReview call the proxy makes when validating a passthrough token (default 10s, previously hardcoded).

## [1.4.0] - 2026-08-20

- Replace --allow-reserved-identity-claims with --allow-reserved-groups, which permits named system:-prefixed groups instead of disabling the reserved-identity guard wholesale. Reserved usernames can no longer be permitted at all. The flag it replaces was added after v1.2.0 and has not appeared in a release.

## [1.3.0] - 2026-08-19

- Update go.opentelemetry.io/otel to v1.44.0 and golang.org/x/mod to v0.40.0, clearing three advisories reported against the dependency tree.
- Harden CI — scope the Prepare Release and GitHub Actions OIDC e2e workflow tokens to the jobs that need them, and stop the e2e fake API server from logging request header values or echoing a caller-controlled body as sniffable content.
- Build against Go 1.26.6, which resolves six reachable Go standard library advisories in crypto/tls, net/http, net/url, html/template, and encoding/asn1.
- Log OIDC token validation failures at `-v=2` with the resolved remote address, instead of `-v=5`. An error from the bearer-token authenticator always means a token was present and failed validation, so it was previously invisible at any verbosity operators run. Request routing is unchanged.
- The readiness endpoint now reports not-ready until the proxy is actually serving, instead of reporting ready as soon as an OIDC issuer initialized. Previously the readiness server started before the proxy's handler chain did, so a pod could join its Service while requests to the proxy port could only queue.
- Audit streaming requests as long-running — exec, attach, portforward, log and proxy are now recorded when the response starts instead of only when the stream ends, so a long session is no longer missing from the audit log while it runs, or entirely if the proxy dies first. These requests now emit a ResponseStarted event as well as ResponseComplete, so audit volume for exec, attach and portforward increases.
- Refuse authenticated identities carrying the Kubernetes-reserved `system:` prefix from token claims, so an OIDC issuer can no longer mint `system:masters` or a service-account username through the proxy's blanket impersonation rights. The check runs before the SubjectAccessReview that authorizes inbound impersonation, and the 403 is audited against the identity that was presented. `system:authenticated` remains permitted as a group because the proxy adds it to every request itself. Name specific reserved groups in `--allow-reserved-groups` if a directory legitimately holds one.
- Audit requests to the core API group (/api/...) are now classified correctly. The audit server config named no legacy API prefix, so every core group request — which is where pods and services live, and with them exec, attach, portforward, log and proxy — was recorded as a non-resource request, with the lowercased HTTP method as its verb and no objectRef, and neither the long-running check nor a watch could ever be recognised. Audit events for these requests now carry the Kubernetes verb (list, create, watch and so on) and an objectRef naming the resource, namespace, name and subresource. If you parse audit logs or write audit policy rules matching on verb or resource, expect the corrected values.

**enhancements:**
 - Multi-issuer OIDC authentication via --authentication-config (AuthenticationConfiguration v1/v1beta1), based on [\#85](https://github.com/TremoloSecurity/kube-oidc-proxy/pull/85) with strict versioned config loading, whole-document validation, a shared CEL compiler and configurable readiness (--readiness-require-all-issuers)

# 1.0.12
**tasks:**
 - 1.0.12 build [\#83](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/83)

# 1.0.11

**bugs:**
 - Critical Vulnerability CVE-2025-68121 [\#78](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/78)

# 1.0.10

**tasks:**
 - 1.0.10 build [\#74](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/74)
 
# 1.0.9

**tasks:**
 - 1.0.9 [\#64](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/64)

**enhancements:**
 - Add flags to be able to configure kubernetes client throttling [\#65](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/65)

# 1.0.8

**tasks:**
 - 1.0.8 [\#61](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/61)

# 1.0.7

**enhancements:**
 - change oidc config to line up with new kube authenticator [\#55](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/55)

**tasks:**
 - 1.0.7 Release [\#54](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/54)

# 1.0.6

**bugs:**
 - e2e tests failing to complete [\#45](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/45)
 - Auditing is not working anymore [\#39](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/39)

**tasks:**
 - 1.0.6 build [\#41](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/41)

# 1.0.5

**tasks:**
 - 1.0.5 build [\#34](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/34)

# 1.0.4

**tasks:**
 - 1.0.4 build [\#29](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/29)

# 1.0.3

**enhancements:**
 - 1.0.3 release [\#26](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/26)

# 1.0.2

**bugs:**
 - CVE-2022-1996 [\#20](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/20)

# 1.0.1

**enhancements:**
 - 1.0.1 [\#14](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/14)

**bugs:**
 - fix timing issues in e2e tests [\#18](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/18)
 - runtime error: slice bounds out of range [:-2] [\#17](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/17)
 
# 1.0.0

**enhancements:**
 - 1.0.0 Release [\#10](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/10)
 - Access logging to standard out [\#2](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/2)
 - create github action to automate builds [\#8](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/8)
 - Switch from alpine --> ubuntu 20.04 [\#9](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/9)
 - Support `kubectl --as` [\#3](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/3)
 - Upgrade KinD [\#1](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/1)

**bugs:**
 - update dependencies [\#5](https://github.com/TremoloSecurity/kube-oidc-proxy/issues/5)
