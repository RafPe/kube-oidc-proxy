# Multi-Issuer OIDC Authentication

kube-oidc-proxy can accept JWTs from several OIDC issuers at once using the
standard Kubernetes [Structured Authentication Configuration](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration)
file format — the same format kube-apiserver consumes since Kubernetes 1.30.
This is particularly useful on managed clusters (EKS, GKE, DOKS, ...) where
apiserver flags cannot be changed and only a single (or no) native OIDC
provider can be configured.

## Enabling

Pass `--authentication-config=/path/to/config.yaml`. This flag is mutually
exclusive with all `--oidc-*` flags. Both `apiserver.config.k8s.io/v1` and
`v1beta1` are accepted; the file is strictly validated at startup (unknown
fields, duplicate issuers, and invalid CEL expressions are rejected). Only
the `jwt:` section is supported; `anonymous:` is rejected.

The file is read once at startup. To apply changes, restart the pods — the
Helm chart annotates the Deployment with a config checksum, so editing
`authenticationConfig.content` triggers a rolling restart automatically.

## Example: GitHub Actions + internal issuer + GitLab

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
# GitHub Actions: no usable groups claim, so CEL synthesizes groups.
- issuer:
    url: https://token.actions.githubusercontent.com
    audiences: ["kube-oidc-proxy.example.com"]
  claimMappings:
    username:
      claim: sub
      prefix: "gha:"
    groups:
      expression: '["github:" + claims.repository_owner]'
  claimValidationRules:
  - expression: 'claims.repository_owner == "my-org"'
    message: "only my-org tokens are accepted"
# Internal issuer with a private CA and a real groups array claim.
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
# GitLab CI: username and groups built with CEL.
- issuer:
    url: https://gitlab.example.com
    audiences: ["kube-oidc-proxy.example.com"]
  claimMappings:
    username:
      expression: '"gitlab:" + claims.project_path'
    groups:
      expression: '["gitlab:ns:" + claims.namespace_path]'
```

RBAC then binds the prefixed identities:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: gha-platform-iac-main
subjects:
- kind: User
  name: "gha:repo:my-org/platform-iac:ref:refs/heads/main"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit
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
