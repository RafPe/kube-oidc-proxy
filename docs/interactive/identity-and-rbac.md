# Token to RBAC

<details>
<summary>Read the guide</summary>

The proxy maps a valid OIDC token to a username and groups. Kubernetes RBAC binds those names to resource permissions.

## Examples from this repository

The explorer uses the existing documentation examples:

| Example | Mapped identity | Resource grant |
| --- | --- | --- |
| [Dex A](../../demo/README.md) | User `oidc-a:alice@example.com` | Demo ClusterRoleBinding to `view` |
| [Dex B](../../demo/README.md) | User `oidc-b:bob@example.com` | Demo ClusterRoleBinding to `view` |
| [GitHub Actions](../getting-started.md#5-give-one-identity-a-role) | Group `gha:repo:my-org/my-repo` | `ci-readers` ClusterRoleBinding to `view` |
| [Explicit impersonation](../authentication.md#inbound-impersonation-kubectl---as) | Target user `ci-viewer` | Separate caller impersonation grant and target binding to `view` |

Dex maps the `email` claim and applies the issuer's username prefix.
Its username and group prefixes are separate configuration fields.
The GitHub Actions example uses CEL expressions to construct the username and groups from repository claims.
Kubernetes matches each resulting subject name exactly. It does not interpret colons or slashes as a group hierarchy.

The default examples use ClusterRoleBindings. They grant the referenced role across namespaces.
The optional RoleBinding variation limits the same ClusterRole to `development`.
It cannot authorize an all-namespaces list request.

Try listing pods, then Secrets. The default `view` role permits pod reads but excludes Secrets.
The explorer models these resources only. It does not reproduce every rule in `view` or any custom aggregation rules.
For a single-object `get` or `delete`, it requires a namespace. The `list` verb represents `kubectl get pods` without a pod name.

## Four separate decisions

| Decision | Mechanism | When the proxy uses it |
| --- | --- | --- |
| Who owns the token? | OIDC authentication or TokenReview | Before forwarding |
| May the caller impersonate another identity? | SubjectAccessReview | When an OIDC request contains explicit impersonation headers |
| May the proxy assert the outbound identity? | API-server impersonation authorization | When the request uses the proxy credential and identity headers |
| May the effective identity access the resource? | Kubernetes authorization | When the API server receives the forwarded request |

Authentication does not grant resource access. A RoleBinding matches a username or group and refers to a Role or ClusterRole.
The proxy does not assign Roles. Kubernetes checks the bindings for each resource request.

Normal Kubernetes users do not require User API objects. Authentication supplies the username and groups.
ServiceAccounts are Kubernetes objects and use names such as `system:serviceaccount:ci:builder`.

## Normal OIDC requests

1. The proxy checks the token against a configured issuer.
2. Claim mappings produce a username and groups.
3. The proxy uses its own Kubernetes credential with impersonation headers.
4. Kubernetes checks whether that credential can impersonate the supplied identity.
5. Kubernetes checks resource permissions for the supplied identity.

The proxy credential needs impersonation grants. The mapped identity needs separate resource grants.
Use distinct username and group prefixes for each issuer. RoleBinding subjects must match the resulting names exactly.

## TokenReview and passthrough

TokenReview asks Kubernetes whether it accepts a bearer token. Passthrough forwards that token after a successful review.
This path can serve Kubernetes-native tokens, including ServiceAccount tokens, through the same proxy endpoint.

An OIDC validation error enters the fallback handler unless the client canceled the request.
The handler requires `--token-passthrough`. It returns 401 when fallback is off, the review rejects the token, or the review dependency fails.
A missing or unparseable bearer token returns 401 directly. It does not enter fallback.

A successful review supplies the identity for audit and access records. The proxy forwards the original token without its own credential.
Kubernetes authenticates the forwarded token and checks its resource permissions. OIDC claim mappings do not apply to this path.

## SubjectAccessReview and explicit impersonation

An OIDC caller can request another identity through `kubectl --as` and related options.
The proxy checks whether the caller can impersonate each requested identity field through SubjectAccessReview.
Without impersonation headers, the authorizer returns immediately and sends no review.

The authentication guide grants group `gha:repo:my-org/my-repo` permission to impersonate `ci-viewer`:

1. OIDC authenticates the GitHub Actions caller and maps its repository group.
2. SubjectAccessReview checks that caller's permission to impersonate the exact user `ci-viewer`.
3. If allowed, the proxy forwards as `ci-viewer` with its own credential.
4. Kubernetes checks the proxy's impersonation grants and the target's resource grants.

The target does not inherit the caller's groups. With `--as=ci-viewer` alone, its effective group is `system:authenticated`.
Removing the caller grant stops the request at the proxy. Removing the proxy grant causes an upstream impersonation refusal.
Removing the target's resource grant leaves the request without access from that binding.

A cached review can answer without a new API call. See [Caching](../caching.md) for expiry and permission-change delays.

Passthrough preserves client impersonation headers. Kubernetes checks those headers against the identity from the original token.
The proxy does not run its SubjectAccessReview path for passthrough requests.

## Disabled impersonation differs from passthrough

With `--disable-impersonation`, OIDC still authenticates the request and consumes its bearer token.
The proxy then forwards without the token, proxy credentials, or generated impersonation headers.
Without client impersonation headers, upstream authentication can identify it as anonymous if the API server permits anonymous authentication for that request.
Otherwise, upstream authentication rejects it. The proxy preserves any client impersonation headers for the upstream to evaluate.

See [Authentication modes](../authentication.md), [Configuration](../configuration.md), and [Request flow](./request-flow.md) for the related controls and code.

</details>
