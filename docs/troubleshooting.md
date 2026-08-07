# Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Pod never becomes Ready in multi-issuer mode | With `readinessRequireAllIssuers: true`, **all** issuers must fetch their JWKS. Check pod logs for the per-issuer initialization messages and confirm each issuer URL is reachable and serves a valid discovery/JWKS document. Set it to `false` to become ready on the first issuer. |
| `authentication-config and --oidc-* flags are mutually exclusive` | You set both `authenticationConfig.content` and one or more `oidc.*` values. Pick one mode. |
| `401 Unauthorized` from the proxy | The token failed OIDC validation — wrong `issuerUrl`/`clientId` (audience), expired token, unmet `requiredClaims`, or a signing algorithm not in `--oidc-signing-algs`. Look for an `AuFail` line in the proxy logs. |
| `403 Forbidden` after a successful login | Authentication worked but RBAC denied the impersonated identity. Grant the mapped username/groups the appropriate roles. Watch for username **prefixes** (e.g. `google:alice@example.com`). |
| `kubectl --as` fails through the proxy | The authenticated user isn't authorized to impersonate that identity (`SubjectAccessReview` denied), or the proxy's ServiceAccount lacks impersonation RBAC for a named `Impersonate-Extra-` key. |
| TLS errors connecting to the proxy | The client's kubeconfig `certificate-authority` must trust the proxy's **serving** certificate (self-signed by the chart, your own Secret, or cert-manager). |
| Confirm which issuers loaded | `kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy \| grep "configured OIDC issuers"`. |

## Reading the request log

Beyond auditing, the proxy logs every request to stdout so a SIEM (via fluentd
or similar) can ingest them. A successful authentication looks like:

```
[2021-11-25T01:05:17+0000] AuSuccess src:[10.42.0.5 / 10.42.1.3, 10.42.0.5] URI:/api/v1/namespaces/openunison/pods?limit=500 inbound:[mlbadmin1 / system:masters|system:authenticated /]
```

- The bracketed prefix is an ISO-8601 timestamp.
- `AuSuccess` indicates authentication succeeded (`AuFail` on failure).
- `src` is the remote address, followed by the `X-Forwarded-For` value if present.
- `URI` is the request path.
- `inbound` is the username, groups, and extra info taken from the JWT.

When impersonation headers are present, an `outbound` section is appended showing
the impersonated identity:

```
[2021-11-25T01:05:17+0000] AuSuccess src:[10.42.0.5 / 10.42.1.3] URI:/api/v1/namespaces/openunison/pods?limit=500 inbound:[mlbadmin1 / system:masters|system:authenticated /] outbound:[mlbadmin2 / group2|system:authenticated /]
```

A failure omits the token information:

```
[2021-11-25T01:05:24+0000] AuFail src:[10.42.0.5 / 10.42.1.3] URI:/api/v1/nodes
```

## See also

- [Usage](./usage.md)
- [Auditing](./tasks/auditing.md)
- [CLI reference](./cli-reference.md)
