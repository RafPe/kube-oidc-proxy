# Unreleased
<!-- next-release -->

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
