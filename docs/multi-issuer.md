# Multi-Issuer OIDC Authentication

kube-oidc-proxy can accept JWTs from several OIDC issuers at once using the
standard Kubernetes [Structured Authentication Configuration](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration)
file format — the same format kube-apiserver consumes since Kubernetes 1.30.
This is particularly useful on managed clusters (EKS, GKE, DOKS, ...) where
apiserver flags cannot be changed and only a single (or no) native OIDC
provider can be configured.

- [Enabling](#enabling)
- [Examples](#examples)
  - [GitHub Actions](#github-actions)
    - [What a token contains](#what-a-token-contains)
    - [Minimal mapping](#minimal-mapping)
    - [Production mapping: trust tiers, audit extras, hard gates](#production-mapping-trust-tiers-audit-extras-hard-gates)
  - [TeamCity](#teamcity-teamcity-oidc-jwt-plugin)
  - [Google service accounts (workloads on GKE / GCE)](#google-service-accounts-workloads-on-gke--gce)
  - [GKE workloads via the cluster's own issuer](#gke-workloads-via-the-clusters-own-issuer-per-serviceaccount-identity)
  - [Internal / custom issuer with a private CA](#internal--custom-issuer-with-a-private-ca)
  - [GitLab CI](#gitlab-ci)
  - [RBAC for the mapped identities](#rbac-for-the-mapped-identities)
- [Security: always use distinct per-issuer prefixes](#security-always-use-distinct-per-issuer-prefixes)
- [Readiness](#readiness)
  - [Issuer records in the log](#issuer-records-in-the-log)
- [Helm](#helm)
- [Notes](#notes)
- [See also](#see-also)

## Enabling

Pass `--authentication-config=/path/to/config.yaml`. This flag is mutually
exclusive with issuer-specific `--oidc-*` flags; the optional OIDC TLS client
certificate/key flags apply to all issuers. Both `apiserver.config.k8s.io/v1` and
`v1beta1` are accepted; the file is strictly validated at startup (unknown
fields, duplicate issuers, and invalid CEL expressions are rejected). Only
the `jwt:` section is supported; `anonymous:` is rejected.

The file is read once at startup. To apply changes, restart the pods — the
Helm chart annotates the Deployment with a config checksum, so editing
`authenticationConfig.content` triggers a rolling restart automatically.

## Examples

Each recipe below is one entry for the `jwt:` list — combine them freely in
a single configuration. Every issuer must use its own distinct username and
groups prefix (see [Security](#security-always-use-distinct-per-issuer-prefixes)).

### GitHub Actions

GitHub mints an OIDC token for a workflow job on request
(`permissions: id-token: write`, then `core.getIDToken('<audience>')` in
`actions/github-script`, or the equivalent in your action of choice). The
audience you pass must equal the issuer's `audiences` entry below. Tokens live
about five minutes.

#### What a token contains

Decode one before writing mappings; the claims are the raw material and a few
of them are not what their names suggest. A `workflow_dispatch` run on `main`
of `my-org/my-repo` carries:

```json
{
  "iss": "https://token.actions.githubusercontent.com",
  "aud": "kube-oidc-proxy.example.com",
  "sub": "repo:my-org/my-repo:ref:refs/heads/main",

  "repository": "my-org/my-repo",
  "repository_id": "7654321",
  "repository_owner": "my-org",
  "repository_owner_id": "1234567",
  "repository_visibility": "internal",
  "enterprise": "my-enterprise",
  "enterprise_id": "2468",

  "ref": "refs/heads/main",
  "ref_type": "branch",
  "ref_protected": "false",
  "base_ref": "",
  "head_ref": "",
  "sha": "bcdb9add7ec52edf83c3a2df6869187302d2fc7b",

  "workflow": "deploy",
  "workflow_ref": "my-org/my-repo/.github/workflows/deploy.yml@refs/heads/main",
  "workflow_sha": "bcdb9add7ec52edf83c3a2df6869187302d2fc7b",
  "job_workflow_ref": "my-org/my-repo/.github/workflows/deploy.yml@refs/heads/main",
  "job_workflow_sha": "bcdb9add7ec52edf83c3a2df6869187302d2fc7b",

  "event_name": "workflow_dispatch",
  "actor": "octocat",
  "actor_id": "555",
  "run_id": "33964329992",
  "run_number": "1",
  "run_attempt": "1",
  "runner_environment": "github-hosted",
  "check_run_id": "101301612960",
  "jti": "f2f7364b-09a2-4422-8ef4-7b8e6c135597",
  "iat": 1788608938, "nbf": 1788608638, "exp": 1788609238
}
```

Things to notice:

- **There is no groups claim.** Every group has to be synthesized with CEL.
- **Every value is a string**, including `ref_protected: "false"`. Compare
  against `"true"` in quotes; a bare boolean never matches.
- **Names can be recycled, IDs cannot.** `repository_owner_id`,
  `repository_id` and `enterprise_id` are the values to pin in validation
  rules; the names are for reading.
- **`sub` is not a stable format.** Newer GitHub tokens embed numeric IDs in it
  (`repo:Owner@<owner_id>/repo@<repo_id>:ref:...`), so a username derived from
  `sub` can change under existing bindings. Build the username from
  `repository` and `ref` instead.
- **`environment` is present only when the job declares one**, and
  `enterprise`/`enterprise_id` only on GitHub Enterprise Cloud. Referencing an
  absent claim makes the whole expression error and the token is rejected, so
  guard optional claims with `has()`.
- **Two workflow refs.** `job_workflow_ref` names the workflow file actually
  running the job, which for a reusable workflow is the called one;
  `workflow_ref` is the top-level caller. Pin `job_workflow_ref` when the
  trust lives in a central reusable workflow.

#### Minimal mapping

A readable username, one group for the owning organisation, and the owner ID
pinned. Enough for a first binding; the next section is what to grow it into.

```yaml
- issuer:
    url: https://token.actions.githubusercontent.com
    audiences: ["kube-oidc-proxy.example.com"]
  claimMappings:
    username:
      expression: '"gha:" + claims.repository + ":" + claims.ref'
    groups:
      expression: '["gha:org:" + claims.repository_owner]'
  claimValidationRules:
  - expression: 'claims.repository_owner_id == "1234567"'
    message: "token not issued for the expected organisation"
```

The token above authenticates as user `gha:my-org/my-repo:refs/heads/main` in
group `gha:org:my-org`. Prefixes must live inside the expression: the `prefix:`
field only applies to the `claim:` form, and a shared `gha:` root keeps every
group this issuer produces in one namespace.

#### Production mapping: trust tiers, audit extras, hard gates

The recipes above show the mechanics. This one is a complete issuer entry for
an organisation that lets many repositories deploy through one proxy. It is
built on three ideas:

1. **RBAC ORs its subjects.** A binding can list several groups, but any one
   of them is enough. There is no way to say "repo X *and* a protected
   branch". So every group must already encode its whole trust condition:
   `gha:protected:my-org/my-repo`, not a bare `gha:protected` that any repo
   could satisfy.
2. **Groups are for RBAC; `extra` is for audit.** Things you would never bind
   a role to (the triggering actor, the run ID, the commit SHA) still belong
   in the audit log. `claimMappings.extra` puts them into `user.extra` of every
   API-server audit event without growing the group list.
3. **Pin numeric IDs, print names.** GitHub names (org, repo, actor) can be
   renamed or re-registered; the numeric IDs cannot. Validation rules pin the
   IDs. Name-based groups stay for readability, ID-based ones for bindings
   that must survive a rename.

```yaml
- issuer:
    url: https://token.actions.githubusercontent.com
    audiences: ["kube-oidc-proxy.example.com"]
  claimMappings:
    username:
      # Audit identity: gha:<org>/<repo>:<ref>. Bind RBAC to groups, not to
      # this, except for one-off pinpoint grants.
      expression: '"gha:" + claims.repository + ":" + claims.ref'
    groups:
      # Base groups every token gets, then conditional tiers a token only
      # gets when it earned them. `cond ? [x] : []` adds x or nothing.
      expression: >-
        [
          "gha:org:" + claims.repository_owner,
          "gha:org-id:" + claims.repository_owner_id,
          "gha:repo:" + claims.repository,
          "gha:workflow:" + claims.job_workflow_ref
        ]
        + (claims.ref_protected == "true" ? ["gha:protected:" + claims.repository] : [])
        + (claims.ref_type == "tag" ? ["gha:tag:" + claims.repository] : [])
        + (has(claims.environment) ? ["gha:env:" + claims.repository + ":" + claims.environment] : [])
    extra:
      # Forwarded as Impersonate-Extra-* headers; visible in audit logs only.
      - key: github.com/actor
        valueExpression: claims.actor
      - key: github.com/actor-id
        valueExpression: claims.actor_id
      - key: github.com/event
        valueExpression: claims.event_name
      - key: github.com/run-id
        valueExpression: claims.run_id
      - key: github.com/run-attempt
        valueExpression: claims.run_attempt
      - key: github.com/sha
        valueExpression: claims.sha
      - key: github.com/repository
        valueExpression: claims.repository
      - key: github.com/repository-id
        valueExpression: claims.repository_id
      - key: github.com/org-id
        valueExpression: claims.repository_owner_id
      - key: github.com/runner
        valueExpression: claims.runner_environment
  claimValidationRules:
    # Hard gates: a token failing any of these is rejected before mapping.
    - expression: 'claims.enterprise == "my-enterprise"'
      message: "token not issued within the expected enterprise"
    - expression: 'claims.enterprise_id == "2468"'
      message: "token not issued within the expected enterprise (id mismatch)"
    - expression: 'claims.repository_owner_id == "1234567"'
      message: "token not issued for the expected organisation"
    - expression: 'claims.repository_visibility != "public"'
      message: "tokens from public repositories are not accepted"
    # Optional: accept only your own runners.
    # - expression: 'claims.runner_environment == "self-hosted"'
    #   message: "only self-hosted runners may reach this cluster"
  userValidationRules:
    - expression: "!user.username.startsWith('system:')"
      message: "username cannot use the system: prefix"
    - expression: "user.groups.all(g, !g.startsWith('system:'))"
      message: "groups cannot use the system: prefix"
```

The `enterprise` and `enterprise_id` claims exist only on GitHub Enterprise
Cloud tokens; drop those two rules on a plain github.com organisation, or the
missing claim makes the rule error and every token is rejected.

**What a token maps to.** For a `workflow_dispatch` run on the unprotected
`main` branch of `my-org/my-repo`, triggered by `octocat`, with no
`environment:` in the job:

| | |
| --- | --- |
| username | `gha:my-org/my-repo:refs/heads/main` |
| groups | `gha:org:my-org` |
| | `gha:org-id:1234567` |
| | `gha:repo:my-org/my-repo` |
| | `gha:workflow:my-org/my-repo/.github/workflows/deploy.yml@refs/heads/main` |
| extra | `github.com/actor=octocat`, `github.com/actor-id=555`, `github.com/event=workflow_dispatch`, `github.com/run-id=…`, `github.com/sha=…`, … |

A push from a protected branch into a job with `environment: prod`, calling a
central reusable workflow, additionally yields `gha:protected:my-org/my-repo`
and `gha:env:my-org/my-repo:prod`, and the workflow group becomes the reusable
workflow's own ref (e.g. `…/platform-workflows/.github/workflows/deploy.yml@refs/tags/v3`).
A release built from a tag yields `gha:tag:my-org/my-repo` instead.

**Which tier to bind to what.**

| Group | Means | Bind it to |
| --- | --- | --- |
| `gha:org:<org>` / `gha:org-id:<id>` | any repo in the org, any ref | read-only roles only (`view`) |
| `gha:repo:<org>/<repo>` | any ref of one repo | that repo's own namespace, `edit` or a purpose-built role |
| `gha:protected:<org>/<repo>` | ref is under a branch/tag protection rule or ruleset | deploy roles for shared or production namespaces |
| `gha:env:<org>/<repo>:<env>` | job passed that environment's protection rules (reviewers, wait timer) | production deploys; strongest signal available |
| `gha:tag:<org>/<repo>` | ref is a tag | release pipelines that cut from tags |
| `gha:workflow:<ref>` | exact workflow file at exact ref | a platform-owned reusable deploy workflow: only jobs calling it get the role, whichever repo they live in |

The environment group is repo-scoped on purpose: environment names are per
repository, so an org-wide `gha:env:prod` would admit every repo's `prod`.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: gha-prod-deployers
  namespace: payments
subjects:
- kind: Group
  name: "gha:env:my-org/payments:prod"        # passed the prod environment gate
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: "gha:workflow:my-org/platform-workflows/.github/workflows/deploy.yml@refs/tags/v3"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
```

Notes:

- The three conditional terms compare **strings**: GitHub emits
  `"ref_protected": "false"` as text, so `== "true"` in quotes is correct
  and a bare `== true` would never match.
- `has(claims.environment)` is mandatory. Without the guard, every token that
  lacks the claim makes the expression error and is rejected.
- Claims left out on purpose: `jti`, `run_number`, `check_run_id`,
  `workflow_sha` and `job_workflow_sha` add nothing over `run_id` and `sha`;
  `base_ref`/`head_ref` are empty outside pull requests. `sub` is not used for
  the username because GitHub is changing its format to embed numeric IDs,
  which would silently change every binding.
- Each group is bound in RBAC by its **exact** string, colons and slashes
  included; the whole value is one opaque group name, not a hierarchy
  Kubernetes interprets.
- `gha:workflow:` is high-cardinality: prefer it for narrow, per-workflow
  bindings and use the org or repo tiers for broad access.

### TeamCity ([teamcity-oidc-jwt](https://github.com/JetBrains/teamcity-oidc-jwt) plugin)

The plugin serves unauthenticated discovery/JWKS under
`<server>/app/oidc-jwt/.well-known/...`. Its raw `sub` is an internal ID
chain (`_Root:project31:bt32`); the external-ID claims make far better
identities:

```yaml
- issuer:
    url: https://teamcity.example.com/app/oidc-jwt
    audiences: ["kube-oidc-proxy.example.com"]
    # certificateAuthority: |     # inline CA if TeamCity uses a private cert
    #   -----BEGIN CERTIFICATE-----
    #   ...
    #   -----END CERTIFICATE-----
  claimMappings:
    username:
      # one identity per build configuration, e.g. "tc:MyProject_Deploy"
      expression: '"tc:" + claims.build_type_external_id'
    groups:
      # bind whole TeamCity projects at once
      expression: '["tc-project:" + claims.project_external_id]'
  claimValidationRules:
  # only default-branch builds may authenticate (drop for branch builds):
  - expression: 'claims.branch_is_default == true'
    message: "only default-branch TeamCity builds may authenticate"
```

Build side: enable the plugin's *Build Parameters* feature with the audience
configured — the token arrives as `env.TEAMCITY_BUILD_OIDC_TOKEN`; or fetch
on demand from `%teamcity.serverUrl%/app/oidc-jwt/issue?aud=<audience>`.

### Google service accounts (workloads on GKE / GCE)

Google-signed ID tokens from `accounts.google.com`; any workload running as
a Google service account (including GKE pods via Workload Identity) can mint
one from the metadata server.

```yaml
- issuer:
    url: https://accounts.google.com
    audiences: ["kube-oidc-proxy.example.com"]
  claimMappings:
    username:
      # → "gcp:deployer@my-project.iam.gserviceaccount.com"
      expression: '"gcp:" + claims.email'
    groups:
      # group per GCP project, derived from the SA email domain
      expression: '["gcp-project:" + claims.email.split("@")[1].split(".")[0]]'
  claimValidationRules:
  # required: with an expression-based username the authenticator does NOT
  # auto-enforce email_verified (that only happens for `claim: email`)
  - expression: 'claims.email_verified == true'
    message: "unverified email claim"
```

Workload side (`format=full` is what includes the `email` claim):

```bash
TOKEN=$(curl -sH "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=kube-oidc-proxy.example.com&format=full")
```

### GKE workloads via the cluster's own issuer (per-ServiceAccount identity)

Alternatively, trust a GKE cluster itself as an issuer — every Kubernetes
ServiceAccount in it becomes a bindable identity, with no Google service
accounts involved. GKE publishes public OIDC discovery for its
ServiceAccount issuer. Use one entry (and one prefix) per source cluster.

```yaml
- issuer:
    url: https://container.googleapis.com/v1/projects/MY_PROJECT/locations/MY_LOCATION/clusters/MY_CLUSTER
    audiences: ["kube-oidc-proxy.example.com"]
  claimMappings:
    username:
      # sub is "system:serviceaccount:<ns>:<sa>"; the prefix makes it
      # collision-proof: → "gke-prod:system:serviceaccount:payments:deployer"
      claim: sub
      prefix: "gke-prod:"
    groups:
      # group per source namespace
      expression: '["gke-prod-ns:" + claims["kubernetes.io"].namespace]'
```

Workload side — a projected token with the right audience, read from the
mounted path and used as the bearer token:

```yaml
volumes:
- name: cluster-access-token
  projected:
    sources:
    - serviceAccountToken:
        audience: kube-oidc-proxy.example.com
        expirationSeconds: 600
        path: token
```

### Internal / custom issuer with a private CA

Systems you control should emit a real groups array — then no CEL is needed
and onboarding new workloads is a change in the issuing system, not in
cluster RBAC:

```yaml
- issuer:
    url: https://auth.internal.example.com
    audiences: ["kubernetes"]
    certificateAuthority: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
  claimMappings:
    username: {claim: sub, prefix: "sys-a:"}
    groups:   {claim: groups, prefix: "sys-a:"}
```

### GitLab CI

```yaml
- issuer:
    url: https://gitlab.example.com
    audiences: ["kube-oidc-proxy.example.com"]
  claimMappings:
    username:
      expression: '"gitlab:" + claims.project_path'
    groups:
      expression: '["gitlab:ns:" + claims.namespace_path]'
```

### RBAC for the mapped identities

Bindings reference the prefixed usernames and groups exactly as the
mappings produce them:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-deployers
subjects:
- kind: User
  name: "tc:MyProject_Deploy"                # a single TeamCity build config
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: "gke-prod-ns:payments"               # every SA in one GKE namespace
  apiGroup: rbac.authorization.k8s.io
- kind: User
  name: "gha:repo:my-org/platform-iac:ref:refs/heads/main"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit                                 # prefer purpose-built roles
  apiGroup: rbac.authorization.k8s.io
```

## Security: always use distinct per-issuer prefixes

All issuers feed the same RBAC namespace. Without distinct prefixes, issuer
B could mint a `sub` or group value that collides with an identity you bound
for issuer A. Give every issuer a unique `prefix:` (or bake a unique prefix
into every CEL expression) and never use `prefix: "-"`-style unprefixed
usernames in a multi-issuer setup.

## Readiness

By default the pod reports ready once at least one issuer's JWKS has been
fetched; issuers still pending are logged and keep initializing in the
background (tokens for them fail with 401 until initialized). Set
`--readiness-require-all-issuers` (Helm: `readinessRequireAllIssuers: true`)
to only report ready when every issuer is initialized. Configuration errors
(invalid YAML, unknown fields, duplicate issuers, bad CEL) always fail
startup, regardless of this flag.

### Issuer records in the log

Issuer state is visible on the normal log stream at the default `-v=0`; you do
not need to raise verbosity to see which issuers are up.

| `event_type` | Level | Fields | Emitted when |
| --- | --- | --- | --- |
| `oidc.issuer.configured` | INFO | `issuer_name`, `issuer_count` | Once per configured issuer at startup. Its `msg` is still `configured OIDC issuers`, so the documented grep keeps working. |
| `oidc.issuer.initialized` | INFO | `issuer_name`, `issuer_state=initialized`, `ready_issuers`, `total_issuers` | That issuer's JWKS loaded and it can now validate tokens. |
| `oidc.issuer.pending` | WARN | `issuer_name`, `issuer_state=pending`, `pending_reason`, `ready_issuers`, `total_issuers` | The pending set or a pending reason **changed**. Not emitted on every readiness scrape, so the newest record per `issuer_name` is that issuer's current state. |
| `readiness.proxy.ready` | INFO | `ready_issuers`, `total_issuers`, `readiness_mode` | Readiness latched to ready. `readiness_mode` is `any` or `all`, mirroring `readinessRequireAllIssuers`. |

`pending_reason` is one of `not_initialized` (the first fetch has not finished
yet), `transient` (the JWKS endpoint is failing but the fetch is being retried),
or `error`. `ready_issuers`/`total_issuers` on any of these records tells you
how far initialization has got without reading the probe.

`issuer_name` is the **configured** issuer name, bounded to 256 characters and
sanitized. The full issuer URL is never logged, on any record. The same
`issuer_name` also appears on `request.access.decided`, which is how you tell
which issuer accepted a given token:

```bash
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy --since=1h \
  | jq -r 'select(.event_type == "request.access.decided" and .event == "AuSuccess")
           | .issuer_name' \
  | sort | uniq -c
```

To list issuers that are currently pending, and why:

```bash
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy \
  | jq -r 'select(.event_type == "oidc.issuer.pending")
           | "\(.issuer_name)\t\(.pending_reason)\t\(.ready_issuers)/\(.total_issuers)"'
```

The [logging reference](./logging.md) has the equivalent LogQL and Splunk
queries and the full field reference.

## Helm

```yaml
authenticationConfig:
  content: |
    apiVersion: apiserver.config.k8s.io/v1
    kind: AuthenticationConfiguration
    jwt:
    - issuer:
        url: https://token.actions.githubusercontent.com
        audiences: ["kube-oidc-proxy.example.com"]
      claimMappings:
        username:
          claim: sub
          prefix: "gha:"
        groups:
          expression: '["github:" + claims.repository_owner]'
    - issuer:
        url: https://auth.internal.example.com
        audiences: ["kubernetes"]
      claimMappings:
        username: {claim: sub, prefix: "sys-a:"}
        groups:   {claim: groups, prefix: "sys-a:"}
readinessRequireAllIssuers: false
```

## Notes

- Signing algorithms: with `--authentication-config`, all valid JOSE signing
  algorithms are accepted (matching kube-apiserver); `--oidc-signing-algs`
  applies only to the single-issuer flag mode.
- Issuer JWKS endpoints must be reachable from the proxy pod network (not
  from the control plane), so private internal issuers work.
- Each issuer entry may carry its own `certificateAuthority` inline.

## See also

- [Getting started](./getting-started.md) — install and choose an auth mode.
- [Configuration reference](./configuration.md) — all flags and impersonation.
- [Local multi-issuer test: kind and GitHub Actions](./operations.md#local-multi-issuer-test-kind-and-github-actions).
- [Architecture: union authenticator](./architecture.md#multi-issuer-union-authenticator).
- [Logging reference](./logging.md) — the `oidc.issuer.*` records and how to
  query them.
