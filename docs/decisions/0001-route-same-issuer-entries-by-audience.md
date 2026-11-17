---
status: proposed
date: 2026-11-17
decision-makers: Rafal P
---

# ADR-0001: Route JWT entries that share an issuer URL by audience

## Context and Problem Statement

One OIDC issuer URL can sign tokens for more than one trust group. Two examples:

* `https://token.actions.githubusercontent.com` signs tokens for workflows in every GitHub organization. An operator can trust the workflows of the own organization and of a vendor organization, each with different rules.
* `https://accounts.google.com` signs tokens for service accounts in every Google Cloud project. An operator can trust internal projects and vendor projects, each with different rules.

Each trust group needs its own claim mappings, prefixes, validation rules and RBAC subjects.

The proxy reads a Kubernetes `AuthenticationConfiguration` (`apiserver.config.k8s.io`). That format cannot express two trust groups on one issuer URL:

1. Upstream validation rejects two `jwt` entries with the same `issuer.url` (`k8s.io/apiserver/pkg/apis/apiserver/validation`, `ValidateAuthenticationConfiguration`).
2. The proxy combines the entries with `tokenunion.NewFailOnError` (`pkg/authn/build.go`). The first entry whose URL matches the token `iss` verifies the token. A failed audience check or a failed claim rule returns an error. The error stops the chain, so a second entry never runs. kube-apiserver uses the same union for its JWT authenticators.

Today an operator must put all trust groups in one entry and select the group in CEL. That entry has one audience list and one `issuer_name`. Logs and metrics cannot show which trust group a request came from.

A second, related limit: the proxy names each issuer by the host of its URL (`pkg/authn/issuer.go`, `IssuerName`). Startup fails when two issuers share a host (`issuers must differ by host`). Two GKE cluster issuers or two EKS cluster issuers in one region share a host, so the proxy refuses them. `docs/integrations.md` recommends one entry per GKE cluster, which the proxy then refuses.

How can the proxy accept several entries for one issuer URL, and give each entry its own rules and name, without trusting unverified token content?

## Decision Drivers

* An unverified claim must never grant access. It can only select which verifier runs.
* A token must never fall through from one entry to another entry.
* The proxy must detect at startup when two entries can match the same token.
* Each entry must have its own name in logs and metrics. Records must not contain the full issuer URL (see `docs/multi-issuer.md`, section on `issuer_name`).
* Existing configuration files must keep the same behavior and the same `issuer_name` values.
* Each entry must keep all upstream validation of a `JWTAuthenticator`, including CEL compilation.

## Considered Options

1. One entry per issuer URL, with the trust group selected in CEL (no code change).
2. A different issuer URL per trust group, from the identity provider.
3. A name derived from a hash of the issuer URL and the audiences.
4. An alias flag that maps an issuer URL to a name.
5. Several entries per issuer URL, routed by a CEL selector.
6. Several entries per issuer URL, routed by `iss` and `aud`, in a proxy-owned configuration kind.

## Decision Outcome

Chosen option: 6, "Several entries per issuer URL, routed by `iss` and `aud`, in a proxy-owned configuration kind".

The token client sets `aud`. GitHub Actions sets it with `core.getIDToken(audience)`. Google sets it with the `audience` parameter of the metadata server. So each trust group can request its own audience. The proxy can check at startup that the audience sets of entries with the same URL do not overlap. This check is not possible for a CEL selector. The upstream format cannot carry a name per entry, so a proxy-owned kind carries the name.

### Configuration kind

```yaml
apiVersion: kube-oidc-proxy.rafpe.github.io/v1alpha1
kind: AuthenticationConfiguration
issuers:
- name: gha-int
  jwt:
    issuer:
      url: https://token.actions.githubusercontent.com
      audiences: ["kube-oidc-proxy-int"]
    claimMappings:
      username:
        expression: '"gha-int:" + claims.repository + ":" + claims.ref'
    claimValidationRules:
    - expression: 'claims.repository_owner_id == "1234567"'
      message: "only the internal organization"
- name: gha-vendor
  jwt:
    issuer:
      url: https://token.actions.githubusercontent.com
      audiences: ["kube-oidc-proxy-vendor"]
    claimMappings:
      username:
        expression: '"gha-vendor:" + claims.repository + ":" + claims.ref'
    claimValidationRules:
    - expression: 'claims.repository_owner_id == "<vendor-owner-id>"'
      message: "only the vendor organization"
```

Rules for the kind:

* The API group is `kube-oidc-proxy.rafpe.github.io`. The version is `v1alpha1`. The kind is `AuthenticationConfiguration`. The group makes it different from the upstream kind with the same name.
* `issuers[].jwt` is an upstream `JWTAuthenticator` in the `apiserver.config.k8s.io/v1` form. The proxy decodes the document as strictly as apimachinery decodes the upstream kind. An unknown field, a duplicate key and a key with the wrong case are errors.
* `issuers[].name` is mandatory. It must be unique. It must be a DNS-1123 subdomain: lowercase letters, digits, `-` and `.`, at most 253 characters. It becomes `issuer_name` in logs and metrics. An operator who moves from the upstream kind can set `name` to the old host and keep the old `issuer_name`. This is not possible when the host has a port, because `:` is not valid in a DNS-1123 subdomain.
* `--authentication-config` accepts both kinds. The proxy selects the decoder from `apiVersion`.
* The upstream kind keeps its current behavior. Its names stay the host of the issuer URL. Its `issuers must differ by host` check stays.

### Startup validation

1. Decode the document strictly.
2. For each entry, convert `jwt` to the internal type. Run `ValidateAuthenticationConfiguration` on a configuration that contains only this entry.
3. Refuse two entries with the same `name`.
4. Refuse two entries with the same issuer URL when their `audiences` share a value.
5. Refuse two entries with the same non-empty `discoveryURL`.
6. Name both entries in each error, as `issuers[i]` and `issuers[j]`. Do not put the full issuer URL in the error.

### Request routing

The `router` authenticator replaces `tokenunion.NewFailOnError` for both kinds.

1. Parse the token payload once without verification. Read `iss` and `aud`. `aud` is a string or an array of strings. Normalize `iss` `accounts.google.com` to `https://accounts.google.com`, as upstream `untrustedIssuer` does.
2. If the token is not a compact JWT, or no entry has the URL `iss`, return `ok=false` with no error. This is the current behavior for a token that no issuer claims.
3. Select the entries with the URL `iss`. If there is one entry, use it. This keeps the current behavior for every upstream configuration.
4. If there are several entries, select the entry whose `audiences` contain a value of the token `aud`.
5. If no entry or more than one entry matches, reject the token with an error. Do not try another entry.
6. Run the full verification of the selected entry only. This includes signature, expiry, audience, claim validation rules and user validation rules.
7. Attribute the request to the name of the selected entry (`AttributeToIssuer`).

The unverified `iss` and `aud` only select the verifier. Acceptance requires the full verification of that entry. The router parses the payload one more time than today. Upstream already parses it once per entry in `hasCorrectIssuer`. The HTTP header limit of the proxy listener bounds the token size.

### Consequences

* Good, because one issuer URL can serve several trust groups, each with its own rules, prefixes and `issuer_name`.
* Good, because the overlap check runs at startup. Two entries can never match the same token.
* Good, because a token never falls through to a second entry.
* Good, because the proxy-owned kind also solves the host collision. Two GKE or EKS cluster issuers on one host have different names.
* Good, because existing configuration files keep their behavior and their `issuer_name` values.
* Bad, because a file of the new kind does not load in kube-apiserver. The docs must say that the kind is proxy-only.
* Bad, because the client chooses `aud`. A vendor workflow can request the audience of the internal entry. Each entry must pin its trust group in `claimValidationRules` with an immutable claim: `repository_owner_id` for GitHub Actions, `sub` or the email domain together with `email_verified` for Google. Audience is routing, not authorization.
* Bad, because each entry fetches its own JWKS, also when two entries share an issuer URL. This doubles the discovery and JWKS requests to that issuer.
* Neutral, because the `issuer_name` contract changes from "the host" to "the configured name, or the host for the upstream kind".

## Implementation Plan

Deliver the work as stacked pull requests on top of the pull request for this ADR. Each pull request must pass `make verify` and `make test` alone.

### PR 1: Resolve issuer names in one place (no behavior change)

* **Affected paths**: `pkg/authn/build.go`, `pkg/authn/issuer.go`, `pkg/probe/probe.go`, `pkg/probe/check.go`, `cmd/app/wiring.go`, the tests beside these files.
* `Build` returns a slice of issuer entries in configuration order. Each entry has the name, the issuer URL and the audiences. It replaces the `[]string` of issuer URLs.
* The probe takes these entries. It keys its state by name, not by issuer URL. It reads the name from the entry and does not call `authn.IssuerName`.
* `pkg/authn/build.go` uses the resolved name in the error for a failed authenticator build.
* **Pattern to avoid**: a call to `IssuerName(url)` outside `pkg/authn`.

### PR 2: Decode and check the new kind

* **Affected paths**: `pkg/authn/config.go`, a new `pkg/authn/v1alpha1/` package for the Go types, `pkg/authn/config_test.go`, `pkg/authn/testdata/`.
* Add the types with `+k8s:deepcopy-gen` markers if the scheme needs them. Register the group in its own scheme.
* `LoadConfiguration` returns the entries for both kinds. The upstream kind uses the host as the name.
* Implement the startup checks in the order of the "Startup validation" section.
* The router does not exist yet. Until PR 3, refuse two entries with the same issuer URL with a clear error.

### PR 3: Route by `iss` and `aud`

* **Affected paths**: a new `pkg/authn/router.go` and `router_test.go`, `pkg/authn/build.go`, `pkg/probe/probe.go`, `pkg/metrics/catalogue.go`.
* Implement the steps of the "Request routing" section. Replace `tokenunion.NewFailOnError` in `buildIssuers`.
* Remove the PR 2 refusal of shared issuer URLs.
* The fake JWT of the readiness probe carries the `iss` of the entry and the first value of its `audiences`. Without the `aud`, the router cannot select the entry.
* Add the reason `audience_unrouted` to the request-path reason set for step 5 of the routing.

### PR 4: Docs, chart and changelog

* **Affected paths**: `docs/multi-issuer.md`, `docs/integrations.md`, `docs/metrics.md`, `docs/logging.md`, `pkg/metrics/catalogue.go` (the `issuer_name` comment), `chart/kube-oidc-proxy/`, `hack/verify-chart-rbac.sh`.
* The chart grants `impersonate` on `userextras/<key>` for each `claimMappings.extra` key that it reads from `authenticationConfig.content`. The chart helper must read the keys of `issuers[].jwt` too. Without this, each request with an extra key of the new kind fails with 403.
* Document the new kind, the startup checks, and the rule that audience is routing only.
* Add GitHub Actions and Google examples with two trust groups on one issuer URL.
* Replace "use one entry per source cluster" in the GKE section with an example of the new kind.
* Change the `issuer_name` contract text.

### Verification

- [ ] A configuration of the upstream kind gives the same `issuer_name` values and the same accept and reject results as before the change.
- [ ] Two entries with the same issuer URL and disjoint audiences start. Only the entry of the token audience accepts the token. The access log shows the name of that entry.
- [ ] Two entries with the same issuer URL and a shared audience fail at startup. The error names both entries by index.
- [ ] The proxy refuses a token whose `aud` matches no entry, or more than one entry. The `authn.oidc.failed` record carries `reason=audience_unrouted`. No other entry runs.
- [ ] The proxy rejects a token that has the correct audience and fails the claim rules of its entry. No other entry runs.
- [ ] Two GKE cluster issuers on `container.googleapis.com` start with the new kind and have different `issuer_name` values.
- [ ] The readiness probe reports each entry, also when two entries share an issuer URL. The fake JWT of the probe carries the first audience of its entry.
- [ ] No code outside `pkg/authn` calls `IssuerName`.
- [ ] An e2e test runs two trust groups behind one fake issuer and the two trust groups have different RBAC results.

## Pros and Cons of the Options

### 1. One entry per issuer URL, trust group selected in CEL

Use a map lookup on an immutable claim, for example `{"1234567": "gha-int"}[claims.repository_owner_id]`. A missing key is a CEL error, so the proxy rejects the token.

* Good, because it needs no code change and loads in kube-apiserver.
* Bad, because all trust groups share one audience list and one `issuer_name`.
* Bad, because the CEL grows with each trust group.
* Neutral, because this option stays valid. The docs keep it as the option for files that must load in kube-apiserver.

### 2. A different issuer URL per trust group

GitHub Enterprise Cloud can add the enterprise slug to the issuer URL. This was not checked against the GitHub documentation for this ADR.

* Good, because the upstream kind can express it.
* Bad, because the vendor must enable it. Google has no equivalent.
* Bad, because the URLs share a host, so the host collision stays.

### 3. Name from a hash of the issuer URL and the audiences

* Bad, because the issuer URL is already unique. The audiences add no uniqueness.
* Bad, because a change to the audience list changes the name, and alerts keyed on `issuer_name` break.
* Bad, because it does not let two entries share an issuer URL.

### 4. Alias flag that maps an issuer URL to a name

* Good, because it keeps the upstream kind.
* Bad, because it cannot give two entries with the same URL different names.

### 5. Several entries per issuer URL, routed by a CEL selector

* Good, because it can select on any claim.
* Bad, because the proxy cannot prove at startup that two selectors do not overlap.
* Bad, because a selector that reads unverified claims is easy to write as authorization by mistake.

## More Information

* 2026-11-17: The changelog fragments are in PR 2 (the new kind) and PR 3 (routing by audience). Those two PRs carry `release/minor`.

* Upstream union: `k8s.io/apiserver/pkg/authentication/token/union`, `NewFailOnError`.
* Upstream issuer check: `k8s.io/apiserver/plugin/pkg/authenticator/token/oidc`, `hasCorrectIssuer` and `untrustedIssuer`.
* Host-only naming and the `issuers must differ by host` check came with pull request #156.
* Revisit this decision if upstream Kubernetes adds names or several entries per issuer URL to `AuthenticationConfiguration`.
