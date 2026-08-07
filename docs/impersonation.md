# Impersonation model

`kube-oidc-proxy` forwards authenticated requests to the API server by
[impersonating](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)
the end user: the proxy authenticates as its **own ServiceAccount** and attaches
`Impersonate-User` / `Impersonate-Group` / `Impersonate-Extra-*` headers for the
mapped identity. Impersonation **replaces, but does not bypass, RBAC** — the API
server still authorizes the impersonated identity.

## Inbound impersonation (`kubectl --as`)

The proxy also supports impersonation headers on **inbound** requests, so
`kubectl --as` works through the proxy. When a request carries impersonation
headers, the proxy first checks — via `SubjectAccessReview` against the API
server — that the authenticated user is allowed to assume that identity. Once
authorized, the proxy forwards the impersonated identity instead of the caller's
own.

## Original-user audit headers

Whenever the proxy impersonates, it also attaches `Extra` headers identifying
the **original** authenticated user, so the API server's audit log records who
really made the request:

| Extra key | When it is sent | Description |
| --- | --- | --- |
| `originaluser.jetstack.io-user` | Always (when impersonating) | The original username. |
| `originaluser.jetstack.io-groups` | When the original user has ≥1 group | The original groups. |
| `originaluser.jetstack.io-uid` | When the original user has a UID | The original user UID. |
| `originaluser.jetstack.io-extra` | When the original identity carries extra info | A JSON-encoded map of arrays with all the original `extra` fields. |

> [!IMPORTANT]
> The `originaluser.jetstack.io-*` keys are a runtime API contract and are
> intentionally left unchanged from upstream. When you use `Impersonate-Extra-`
> headers, the proxy's ServiceAccount must be explicitly authorized via RBAC to
> impersonate that extra key — extras are treated as subresources that require
> explicit authorization.

## Disabling impersonation

Impersonation can be turned off entirely with `--disable-impersonation`, in
which case authenticated requests are forwarded as-is. See
[no-impersonation](./tasks/no-impersonation.md).

## See also

- [Extra impersonation headers](./tasks/extra-impersonation-headers.md)
- [No impersonation](./tasks/no-impersonation.md)
- [Auditing](./tasks/auditing.md)
- [Security considerations](./security.md)
