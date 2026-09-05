<p align="center">
  <img src="./assets/social-card.png" alt="kube-oidc-proxy — OIDC authentication proxy for managed Kubernetes, with multi-issuer support" width="820">
</p>

[![Build](https://github.com/RafPe/kube-oidc-proxy/actions/workflows/build.yaml/badge.svg)](https://github.com/RafPe/kube-oidc-proxy/actions/workflows/build.yaml)
[![E2E](https://github.com/RafPe/kube-oidc-proxy/actions/workflows/e2e.yaml/badge.svg)](https://github.com/RafPe/kube-oidc-proxy/actions/workflows/e2e.yaml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/rafpe/kube-oidc-proxy)](https://goreportcard.com/report/github.com/rafpe/kube-oidc-proxy)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/RafPe/kube-oidc-proxy/badge)](https://securityscorecards.dev/viewer/?uri=github.com/RafPe/kube-oidc-proxy)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kube-oidc-proxy)](https://artifacthub.io/packages/search?repo=kube-oidc-proxy)

# kube-oidc-proxy

A reverse proxy that brings OIDC login to managed Kubernetes clusters, and accepts tokens from several issuers through one proxy.

## Why

- **The problem:** managed clusters (EKS, GKE, AKS, …) don't let you set the API server's `--oidc-*` flags, so you can't wire in your own OIDC provider.
- **The fix:** the proxy validates the bearer token and impersonates the user against the API server — your existing RBAC stays authoritative.
- **What's different:** one proxy can accept tokens from many issuers at once via a Kubernetes `AuthenticationConfiguration`, with CEL to map claims to usernames, groups and audit fields.

## How it works

The proxy sits in front of the API server, validates the bearer token against one or more OIDC issuers, and maps the token's claims to a Kubernetes identity. It then forwards the request using its **own ServiceAccount** plus impersonation headers for the mapped user. The API server evaluates **RBAC** for that user as usual — OIDC login without ever touching the `--oidc-*` flags.

![kube-oidc-proxy — component view](./docs/c4/diagrams/structurizr-Components.png)

See [architecture](./docs/architecture.md) for the full C4 model (system context, containers) and the request-flow sequence.

## Does it fit?

- **You need it** when the API server's OIDC flags are out of reach, when several identity providers must authenticate to one cluster, or when a CI system's OIDC tokens should become Kubernetes identities without long-lived credentials.
- **What it changes:** clients talk to the proxy instead of the API server, so they need a kubeconfig pointing at it; the API server's own endpoint keeps working for everyone else. The proxy's ServiceAccount is allowed to impersonate any user, so its Deployment and RBAC are privileged.
- **What it does not do:** it never decides what an identity may do. Authorization stays in the API server's RBAC, for the mapped identity, on every request.
- **Tested against** the current Kubernetes minor and the two before it, on kind; the versions are declared in [`test/e2e/versions/kubernetes-versions.json`](./test/e2e/versions/kubernetes-versions.json). Helm 3+, developed against Helm 4.

## Quickstart

This is a smoke test, not a production install: it needs a cluster, `kubectl`,
Helm 3+, an OIDC issuer, and an ID token from that issuer in `$ID_TOKEN`.
[Getting started](./docs/getting-started.md) is the complete first
installation, ingress, RBAC and verification included.

Install from the published, signed OCI chart:

```sh
helm install kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  --namespace kube-oidc-proxy --create-namespace \
  --set oidc.clientId=<client-id> \
  --set oidc.issuerUrl=https://<issuer-url> \
  --set oidc.usernameClaim=email
```

Add `--version <x.y.z>` to pin a specific [release](https://github.com/rafpe/kube-oidc-proxy/releases); omit it for the latest. To install from a local checkout instead, swap the chart reference for `./chart/kube-oidc-proxy`.

Verify — port-forward the proxy and ask the cluster who you are:

```sh
kubectl -n kube-oidc-proxy port-forward svc/kube-oidc-proxy 8443:443 &
kubectl --server=https://127.0.0.1:8443 --insecure-skip-tls-verify \
  --token="$ID_TOKEN" auth whoami
```

```text
ATTRIBUTE   VALUE
Username    alice@example.com
Groups      [system:authenticated]
```

The username is the token's `email` claim as configured above; add
`--set oidc.usernamePrefix=google:` to namespace it, which matters as soon as a
second issuer is added.

## Multi-issuer authentication

Accept tokens from several issuers at once via a Kubernetes `AuthenticationConfiguration`, each with its own audiences, claim mappings and validation rules:

```yaml
authenticationConfig:
  content: |
    apiVersion: apiserver.config.k8s.io/v1
    kind: AuthenticationConfiguration
    jwt:
      - issuer:
          url: https://accounts.google.com
          audiences: [my-google-client]
        claimMappings:
          username: { claim: email, prefix: "google:" }
      - issuer:
          url: https://token.actions.githubusercontent.com
          audiences: [kube-oidc-proxy.example.com]
        claimMappings:
          username:
            expression: '"gha:" + claims.repository + ":" + claims.ref'
          groups:
            expression: '["gha:org:" + claims.repository_owner]'
```

> [!NOTE]
> When `authenticationConfig.content` is set, the chart passes `--authentication-config` and does not render the issuer-specific `oidc.*` values. Optional `oidc.tlsClient` credentials apply to every issuer in either configuration.

Format, readiness and the per-issuer prefix rule: [multi-issuer authentication](./docs/multi-issuer.md). A recipe per identity provider: [integrations](./docs/integrations.md).

## Features

- **Multi-issuer OIDC** — accept tokens from many providers through one proxy, with CEL claim mappings and validation rules.
- **Single-issuer OIDC** — standards-based, with flag parity with the API server's authenticator.
- **Impersonation, not credential sharing** — RBAC stays authoritative; `kubectl --as` is gated by `SubjectAccessReview`.
- **Configurable readiness** — become ready on the first issuer, or wait for all.
- **Token passthrough** for non-OIDC bearer tokens, validated via `TokenReview`.
- **Auditable** — one structured log stream with a per-request ID that is also the API server's audit ID; an optional audit log of its own.
- **Hardened Helm chart** — flexible TLS, PodDisruptionBudget, locked-down SecurityContext by default.

## Documentation

| I want to… | Read |
| --- | --- |
| Understand how it works: request flow, impersonation, readiness | [Architecture](./docs/architecture.md) |
| Install it and get the first request through | [Getting started](./docs/getting-started.md) |
| Choose a configuration and understand identities, `kubectl --as`, passthrough | [Authentication and identity](./docs/authentication.md) |
| Connect an identity provider: GitHub Actions, GitLab, Google, GKE, TeamCity, my own | [Integrations](./docs/integrations.md) |
| Configure several issuers in one proxy | [Multi-issuer authentication](./docs/multi-issuer.md) |
| Debug a failing request, watch traffic, upgrade, plan for outages | [Operations](./docs/operations.md) |
| Read the structured log or ship it to a SIEM | [Logging reference](./docs/logging.md) |
| Audit who did what, on the proxy and the API server | [Auditing](./docs/auditing.md) |
| Tune the review caches and the header cap | [Caching and API-server protection](./docs/caching.md) |
| Look up a flag | [Configuration reference](./docs/configuration.md) |
| Look up a chart value | [Chart values reference](./chart/kube-oidc-proxy/README.md) |
| Try it locally with no identity provider | [Multi-issuer demo](./demo/README.md) |
| Contribute: build, test, run the e2e suite | [Development](./docs/development.md) |
| Maintain: cut a release, recover a failed one, Artifact Hub | [Releases](./docs/releases.md) |

## Project status & lineage

> [!NOTE]
> This is a fork of [`TremoloSecurity/kube-oidc-proxy`](https://github.com/TremoloSecurity/kube-oidc-proxy), itself a fork of the original [`jetstack/kube-oidc-proxy`](https://github.com/jetstack/kube-oidc-proxy). The addition in this fork is **multi-issuer authentication** via `--authentication-config`: a single proxy can accept tokens from several OIDC issuers at once. Optional serving-certificate integration still uses [`jetstack/cert-manager`](https://github.com/jetstack/cert-manager).

## Contributing

Contributions are welcome — issues and pull requests both. Building requires Go 1.26. [Development](./docs/development.md) covers running the proxy from source, the hermetic `make e2e` end-to-end suite and a local multi-issuer test against a real GitHub Actions token; the [demo](./demo/README.md) stands the whole flow up with one command.

Releases are review-gated and label-driven: every ordinary PR carries exactly one `release/*` label and every non-skip PR adds a changelog fragment, and ordinary merges never publish. The exact flow and its recovery procedure are in the [maintainer runbook](./docs/releases.md).
