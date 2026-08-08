# Security Policy

`kube-oidc-proxy` sits directly on the authentication path to your Kubernetes
API server, so security reports are taken seriously and handled with priority.

## Supported versions

Security fixes are provided for releases **1.1.0 and newer** — the point at
which this project became an independent fork. Please upgrade to a supported
release before reporting an issue.

| Version             | Supported |
| ------------------- | --------- |
| >= 1.1.0            | ✅        |
| < 1.1.0 (pre-fork)  | ❌        |

## Reporting a vulnerability

**Please do not report security issues in public GitHub issues, pull requests,
or discussions.**

Instead, report privately via GitHub's
**[Report a vulnerability](https://github.com/RafPe/kube-oidc-proxy/security/advisories/new)**
(the repository's *Security → Advisories* tab). This opens a private advisory
visible only to you and the maintainer.

Please include:

- the affected version or image tag (e.g. `ghcr.io/rafpe/kube-oidc-proxy:1.1.0`),
- a clear description and the security impact,
- steps to reproduce or a proof of concept,
- any suggested remediation, if you have one.

## What to expect

- **Acknowledgement** of your report, typically within a few days.
- **Assessment**: the report is validated and its severity/impact evaluated;
  you'll be kept informed of progress.
- **Fix & release**: a fix is prepared and shipped in a new release. Timelines
  depend on severity and complexity.
- **Coordinated disclosure**: a disclosure date is agreed once a fixed release
  is available, and you are credited for the report if you wish.

## Scope

**In scope** — issues in this proxy's own logic, for example:

- OIDC token validation and multi-issuer handling,
- impersonation and authorization (`SubjectAccessReview`),
- client-IP / trusted-proxy resolution used for audit and impersonation extras,
- request handling, token passthrough, and TLS serving.

**Out of scope**, for example:

- misconfiguration of your own deployment, Kubernetes RBAC, or identity provider,
- vulnerabilities in third-party dependencies that are already surfaced by this
  project's automated scanning (see below) — those are remediated via routine
  dependency updates, not the private advisory process,
- attacks that require an already-compromised cluster, node, or the proxy's
  own ServiceAccount credentials.

## Dependency & supply-chain security

Dependency CVEs are surfaced automatically by **Dependabot** and by
**`govulncheck`** running in CI on every pull request and push. Third-party
GitHub Actions are pinned to commit SHAs, and an
[OpenSSF Scorecard](https://securityscorecards.dev/) workflow reports on the
project's supply-chain posture.

## Upstream

This project is a fork of
[TremoloSecurity/kube-oidc-proxy](https://github.com/TremoloSecurity/kube-oidc-proxy)
(originally [jetstack/kube-oidc-proxy](https://github.com/jetstack/kube-oidc-proxy)).
See [MAINTAINING.md](./MAINTAINING.md) for how this fork tracks upstream security
fixes. If a vulnerability affects upstream as well, please also consider
reporting it to the upstream maintainers.
