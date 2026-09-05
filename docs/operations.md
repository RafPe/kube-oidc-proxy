# Operations

Running the proxy in production: the first checks when a request fails,
security, troubleshooting, watching traffic, and the lifecycle procedures for
upgrades, outages and sizing. Building and testing the proxy itself is in
[development](./development.md).

- [First checks](#first-checks)
- [Security](#security)
  - [Hardening checklist](#hardening-checklist)
- [Troubleshooting](#troubleshooting)
  - [Reading the request log](#reading-the-request-log)
  - [Watching requests](#watching-requests)
  - [Turning up verbosity](#turning-up-verbosity)
- [Upgrade and rollback](#upgrade-and-rollback)
- [Availability and issuer outages](#availability-and-issuer-outages)
- [Capacity and sizing](#capacity-and-sizing)
- [See also](#see-also)

## First checks

When a request through the proxy fails and you have five minutes, run these
in order. Each one halves the search space.

1. **Did the request reach the proxy?** Read every replica, not one pod:

   ```bash
   kubectl -n kube-oidc-proxy logs -l app.kubernetes.io/name=kube-oidc-proxy --since=10m --tail=-1 \
     | jq -r 'select(.event_type == "request.access.decided")
              | [.time, .event, .reason // "-", .inbound_user // "-", .http_method, .path] | @tsv'
   ```

   Nothing at all means the request never arrived: the load balancer,
   ingress or certificate in front of the proxy answered instead. Bypass
   them with a port-forward to the Service to prove the token and the
   mappings are fine, then fix the path in front.

2. **`AuFail`?** The proxy refused it and `reason` says why, from a
   [closed vocabulary](./logging.md#reason-vocabularies): `unauthorized` is
   the token itself (expired, wrong audience, failed validation rule),
   `impersonation_denied` is a `kubectl --as` the caller may not perform.

3. **`AuSuccess` but the client saw 403?** Authentication worked and the API
   server refused the action. Join the access record with
   `request.response.completed` to see the upstream status per request, then
   read `kubectl ... -v 8` for the API server's message: an RBAC denial names
   the mapped identity, a missing grant for the proxy's own ServiceAccount
   names a `userextras/<key>` or `subjectaccessreviews`.

4. **Still unclear?** Turn verbosity up to `1` and trace the request by its
   ID; both are under [watching requests](#watching-requests).

The [troubleshooting table](#troubleshooting) maps each symptom to its fix.

## Security

- **The proxy is a privileged component.** Its ServiceAccount can impersonate
  users, groups, and extras against the API server. Restrict who can modify its
  Deployment and RBAC, and keep the chart's hardened defaults (non-root,
  read-only root filesystem, dropped capabilities, seccomp `RuntimeDefault`).
- **Impersonation replaces, but does not bypass, RBAC.** The API server still
  authorizes the impersonated identity. Keep API-server RBAC tight; the proxy
  decides *who* the request is, not *what* they may do.
- **Terminate and verify TLS end to end.** Clients must trust the proxy's
  serving certificate, and each OIDC issuer's TLS must be verifiable
  (`oidc.caPEM` / inline `certificateAuthority` for private CAs).
- **Scope audiences and required claims.** Use `audiences` / `--oidc-client-id`
  and `requiredClaims` so tokens minted for other systems can't be replayed
  against the cluster — especially for machine issuers like GitHub Actions.
- **Mind username prefixes across issuers.** In multi-issuer mode, distinct
  `prefix` values stop one issuer's `alice` from colliding with another's.
- **Use token passthrough deliberately.** `--token-passthrough` forwards
  non-OIDC tokens after a TokenReview; only enable it (and constrain
  `--token-passthrough-audiences`) when you understand the tokens involved.
  TokenReview results are cached, so a **revoked token keeps working for up to
  `--token-passthrough-cache-success-ttl`** (default 10s). Set it to `0` to
  disable — see [Caching and API-server protection](./caching.md#tokenreview-result-cache).
- **Know the caching tradeoffs.** TokenReview results and impersonation
  `SubjectAccessReview` decisions are both cached with 10s TTLs by default, so
  token revocation and RBAC grant/revoke changes lag by up to one TTL. The
  tradeoffs and the per-request-revocation settings are documented in
  [Caching and API-server protection](./caching.md).
- **Configure trusted proxies before trusting forwarded IPs.** By default the
  proxy ignores `X-Forwarded-For` and uses the direct peer as the client IP, so
  clients cannot forge the logged or impersonated client IP. Set
  `--trusted-proxies` only to CIDRs of proxies you run directly in front of it —
  see [Trusted proxies and client IP](./configuration.md#trusted-proxies-and-client-ip).

### Hardening checklist

The bullets above as checks to run before, and periodically after, exposing
the proxy. Each names what to look at.

| Check | How |
| --- | --- |
| Only the platform team can change the proxy's Deployment, ClusterRole and ClusterRoleBinding | `kubectl auth can-i --list --as=<a typical user>` in the release namespace shows no write on them; the values file and RBAC live in reviewed Git history. |
| Every issuer entry pins an audience specific to this proxy | No `audiences` value is shared with another system; for CI providers, validation rules pin numeric organisation or project IDs, not names ([integrations](./integrations.md)). |
| Every issuer has its own username and groups prefix | No two `jwt:` entries produce identities that could collide ([multi-issuer](./multi-issuer.md#security-always-use-distinct-per-issuer-prefixes)). |
| Nothing binds a role to a bare `system:authenticated` or to a prefix-less name | `kubectl get clusterrolebindings,rolebindings -A -o yaml \| grep -B2 'name: system:authenticated'` returns only the Kubernetes defaults. |
| Impersonation grants (`kubectl --as`) are scoped with `resourceNames` | Any ClusterRole with `impersonate` on `users` or `groups` and no `resourceNames` is deliberate and documented ([inbound impersonation](./authentication.md#inbound-impersonation-kubectl---as)). |
| Clients verify the proxy's certificate | No kubeconfig in use carries `insecure-skip-tls-verify`; the certificate covers the hostname clients use, on the ingress or the Service. |
| The proxy verifies each issuer's certificate | Private CAs are inline (`certificateAuthority`, `oidc.caPEM`); the pod's egress to every issuer's JWKS is allowed by network policy and nothing else on that path is. |
| Forwarded client IPs are trusted only from your own hops | `--trusted-proxies` is empty, or lists exactly the CIDRs of the ingress or load balancer in front ([trusted proxies](./configuration.md#trusted-proxies-and-client-ip)). |
| Token passthrough is off unless understood | `tokenPassthrough.enabled: false`, or the audiences are constrained and the success TTL is deliberate ([caching](./caching.md#tokenreview-result-cache)). |
| Audit data is handled as sensitive | Audit events and access records carry usernames, groups and `extra` values; the log pipeline they go to has the same access controls as the API server's audit log ([auditing](./auditing.md)). |
| The pod security defaults are intact | `helm get values` shows no override of `podSecurityContext` or `securityContext`; file audit logs use an `emptyDir` rather than a writable root filesystem. |

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Pod never becomes Ready in multi-issuer mode | With `readinessRequireAllIssuers: true`, **all** issuers must fetch their JWKS. Check pod logs for the per-issuer initialization messages and confirm each issuer URL is reachable and serves a valid discovery/JWKS document. Set it to `false` to become ready on the first issuer. |
| `authentication-config and --oidc-* flags are mutually exclusive` | You set both `authenticationConfig.content` and one or more `oidc.*` values. Pick one mode. |
| `401 Unauthorized` from the proxy | The token failed OIDC validation — wrong `issuerUrl`/`clientId` (audience), expired token, unmet `requiredClaims`, or a signing algorithm not in `--oidc-signing-algs`. Look for an `AuFail` line with `reason=unauthorized` in the proxy logs (`event_type=request.access.decided`). |
| `403 Forbidden` after a successful login | Authentication worked but RBAC denied the impersonated identity. Grant the mapped username/groups the appropriate roles. Watch for username **prefixes** (e.g. `google:alice@example.com`). |
| `403 Forbidden` on **every** request from one issuer, right after `AuSuccess` | The API server refused the proxy's own ServiceAccount, not your identity: it authorizes each `Impersonate-Extra-<key>` header separately as `impersonate` on `userextras/<key>`, and an issuer that maps `claimMappings.extra` sends keys the ClusterRole may not name. The response body says which key (`cannot impersonate resource "userextras/..."`); see it with `kubectl ... -v 8`. The chart's ClusterRole grants every key declared in `authenticationConfig.content` and in `extraImpersonationHeaders.headers`; check the rendered ClusterRole for `userextras/<key>` lines, and if your chart version predates that or you install from raw manifests, grant them yourself — see [multi-issuer: Helm](./multi-issuer.md#helm). |
| `kubectl auth whoami` says the API "is not enabled in the cluster or you do not have permission" | kubectl prints that for any non-2xx from the `selfsubjectreviews` endpoint, so it hides a 403 or a 404 from something in front of the proxy. Rerun with `-v 8` to see the real status and body, then follow the matching row here. |
| `404 not found` with `Server: awselb/2.0`, or an ingress controller's default 404 page | The request never reached the proxy. A load balancer or ingress answered from its default action because no rule matched the `Host`. Compare against a hostname that is known to work on the same entrypoint, and check `kubectl get ingress` and `kubectl get endpoints` for the release. |
| `x509: certificate is valid for ..., not <your-host>` | The TLS-terminating layer in front of the proxy served its default certificate because none covers your hostname. Add a certificate for the name (`ingress.tls` in the chart, or on the load balancer listener), or use a hostname the existing certificate covers. `--insecure-skip-tls-verify` is acceptable only while testing. |
| `error: unknown flag: --logging-format` at pod start | The image is older than the chart: `--logging-format` arrived in 1.7.0. The chart defaults `image.tag` to its `appVersion`; a chart installed from a checkout whose `Chart.yaml` baseline lags the release deploys the older image. Set `image.tag` explicitly or update the baseline. |
| Log queries return nothing although requests were made | With more than one replica, `kubectl logs deploy/<name>` reads a single pod. Select all of them with `-l app.kubernetes.io/name=kube-oidc-proxy` — see [watching requests](#watching-requests). |
| A value set on a previous install "disappears" after `helm upgrade --reuse-values` | `--reuse-values` renders with the values stored by the last release and does not merge the new chart's defaults, so a key added in a newer chart is unset. Upgrade with `-f values.yaml` instead. |
| `kubectl --as` fails through the proxy with `403` | The authenticated user isn't authorized to impersonate that identity (`SubjectAccessReview` denied), or the proxy's ServiceAccount lacks impersonation RBAC for a named `Impersonate-Extra-` key. The `AuFail` record carries `reason=impersonation_denied` with `target_kind` and `target_name`. |
| `kubectl --as` fails through the proxy with `500`, `reason=internal_error` | The proxy could not *ask* whether impersonation is allowed: its ServiceAccount is not permitted to create `SubjectAccessReview`s. The `authz.sar.failed` record carries `reason=authorization_dependency_error` and the API server's message (`cannot create resource "subjectaccessreviews"`). Grant the proxy's ServiceAccount `create` on `subjectaccessreviews` in `authorization.k8s.io`; a chart whose ClusterRole predates that grant needs it added by hand. Plain token requests are unaffected, since they never trigger a review. |
| `431 Request Header Fields Too Large` on `kubectl --as` | The request carried more impersonation header values (user + every group, uid and extra value) than the proxy accepts per request (default 64). Raise `--max-impersonation-header-values` (`maxImpersonationHeaderValues` in the chart) if the identity legitimately needs more — see [the header value cap](./caching.md#impersonation-header-value-cap). |
| RBAC impersonation grant/revoke takes up to 10s to take effect through the proxy | Expected: impersonation `SubjectAccessReview` decisions are cached. A revoked grant keeps working for up to `--subject-access-review-cache-allow-ttl`; a new grant keeps failing for up to `--subject-access-review-cache-deny-ttl` (both default `10s`). Set either TTL to `0` to re-check that class on every request — see [the SAR decision cache](./caching.md#subjectaccessreview-decision-cache). |
| TLS errors connecting to the proxy | The client's kubeconfig `certificate-authority` must trust the proxy's **serving** certificate (self-signed by the chart, your own Secret, or cert-manager). |
| Trace one request end to end | Take `request_id` from any proxy record (the client also gets it back in the `Audit-ID` response header) and grep every proxy record for it; the same value is the kube-apiserver audit `auditID` — see [correlation](./logging.md#correlation). |
| An issuer is stuck | `event_type=oidc.issuer.pending` names the issuer and a `pending_reason`; it is emitted on state change, so the newest record per issuer is current — see [issuer state](./logging.md#issuer-state). |
| Confirm which issuers loaded | `kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy \| jq -r 'select(.event_type == "oidc.issuer.initialized") \| .issuer_name'` — one line per issuer whose JWKS loaded, in this pod. The current state of each issuer, pending or initialized, is the [issuer state query](./logging.md#issuer-state). |
| A revoked passthrough token still works / a newly valid one is rejected | The TokenReview result cache. A revoked token passes for up to `--token-passthrough-cache-success-ttl`; a token that just became valid can be rejected for up to `--token-passthrough-cache-failure-ttl` (both default 10s). Set either flag to `0` to disable that side — see [the TokenReview cache](./caching.md#tokenreview-result-cache). |

### Reading the request log

The proxy logs every request to stdout as a single JSON object per record, so a
SIEM (via fluentd or similar) can ingest them without a custom parser. Every
value is sanitized: control characters are stripped, so nothing a client sends
can inject a second record or fake a field.

The record to key on is `event_type=request.access.decided`: exactly one per
request, on every path — impersonation, no-impersonation, TokenReview
passthrough, and every failure class. `event` (`AuSuccess` / `AuFail`) is
unchanged from earlier releases, so existing SIEM rules keep matching. The
[logging reference](./logging.md) has the full field reference, the event
registry and worked Loki/Splunk queries; this section is the operator's
short version.

A successful authentication looks like this (one line in the stream, wrapped
here to read):

```json
{"time":"2026-09-04T10:53:24.615018Z","level":"INFO","msg":"access decision","schema_version":1,
 "component":"request","event_type":"request.access.decided",
 "request_id":"7f1a9c1e-6a2b-4a1f-9f0e-3d9d1c2b5a04","event":"AuSuccess","src_ip":"10.42.1.3",
 "path":"/api/v1/namespaces/default/pods","forwarded_for_untrusted":"10.42.0.5","http_method":"GET",
 "auth_method":"oidc","issuer_name":"corp","k8s_verb":"list","k8s_api_group":"","k8s_resource":"pods",
 "k8s_namespace":"default","decision":"allow","inbound_user":"alice@example.com",
 "inbound_groups":["platform-admins","system:authenticated"],
 "inbound_extra":{"Remote-Client-IP":["10.42.1.3"]},"inbound_extra_omitted":1}
```

When impersonation headers are present, the `outbound_*` fields report the
impersonated identity alongside the authenticated one:

```json
{"time":"2026-09-04T10:53:24.615236Z","level":"INFO","msg":"access decision","schema_version":1,
 "component":"request","event_type":"request.access.decided",
 "request_id":"c0a8f1d2-9b34-4d7e-8a11-6e2f0b7c4d55","event":"AuSuccess","src_ip":"10.42.1.3",
 "path":"/api/v1/namespaces/default/pods","http_method":"GET","auth_method":"oidc",
 "k8s_verb":"list","k8s_api_group":"","k8s_resource":"pods","k8s_namespace":"default",
 "decision":"allow","inbound_user":"alice@example.com",
 "inbound_groups":["platform-admins","system:authenticated"],
 "outbound_user":"bob@example.com","outbound_groups":["developers","system:authenticated"]}
```

An `AuFail` is a rejection, and `reason` says which kind. **Not every `AuFail`
means the token failed to authenticate.** An authentication failure has no
trustworthy identity to attribute the request to, so it carries no `inbound_*`
fields:

```json
{"time":"2026-09-04T10:53:24.615241Z","level":"INFO","msg":"access decision","schema_version":1,
 "component":"request","event_type":"request.access.decided",
 "request_id":"3b7c5e10-4f28-49a6-b0d3-8c1e5a90f2b7","event":"AuFail","src_ip":"10.42.1.3",
 "path":"/api/v1/nodes","http_method":"GET","auth_method":"oidc","decision":"deny",
 "reason":"unauthorized"}
```

An **authorization** failure is also an `AuFail`, and there the token *did*
authenticate: the request is refused because the authenticated user may not
impersonate the identity it asked for, or asked for a reserved one. Those
records carry the full `inbound_*` identity plus `target_kind` and
`target_name` naming what was refused:

```json
{"time":"2026-09-04T10:53:24.615318Z","level":"INFO","msg":"access decision","schema_version":1,
 "component":"request","event_type":"request.access.decided",
 "request_id":"9d41a7b8-2c60-4e15-9f83-71ab0c3d6e42","event":"AuFail","src_ip":"10.42.1.3",
 "path":"/api/v1/namespaces/default/pods","http_method":"GET","auth_method":"oidc",
 "k8s_verb":"list","k8s_api_group":"","k8s_resource":"pods","k8s_namespace":"default",
 "decision":"deny","reason":"impersonation_denied","target_kind":"user",
 "target_name":"bob@example.com","inbound_user":"alice@example.com",
 "inbound_groups":["platform-admins","system:authenticated"]}
```

So: `reason=unauthorized` or `no_username_claim` means the token never
authenticated and there is no identity in the record. `reason=impersonation_denied`,
`reserved_identity` or `too_many_impersonation_values` means it authenticated
fine and was then refused — `inbound_user` is real and worth investigating.

| Field | Meaning |
| --- | --- |
| `event_type` | `request.access.decided` on this record. The machine-readable record shape — filter on it rather than on `msg`. |
| `event` | `AuSuccess` when the request authenticated and was proxied, `AuFail` when it was rejected. Frozen: SIEM rules key on it. |
| `request_id` | Correlates every record this request produced, is sent upstream as the `Audit-ID` header (so it is also the kube-apiserver audit `auditID`), and is echoed to the client — see [correlation](./logging.md#correlation). |
| `decision` / `reason` | `allow` or `deny`, and on a denial which of the closed [reason values](./logging.md#reason-vocabularies) applies. |
| `src_ip` | The **authoritative** client IP. It is the direct peer unless that peer is inside a configured `--trusted-proxies` network, in which case the forwarded chain is walked right-to-left past the trusted hops — see [Trusted proxies and client IP](./configuration.md#trusted-proxies-and-client-ip). This is the field to use for identity and rate limiting. |
| `forwarded_for_untrusted` | The raw `X-Forwarded-For` chain exactly as the client sent it, present only when the header was set. It is forensic data that any client can forge — never treat it as identity. |
| `path` | The request path. The query string is deliberately excluded, because it can carry tokens. |
| `http_method`, `k8s_verb`, `k8s_resource`, `k8s_namespace` | The HTTP method, and the Kubernetes API dimensions the request-info resolver determined. The `k8s_*` fields are absent on non-resource paths such as `/healthz` and discovery. |
| `auth_method` | `oidc`, `tokenreview` (passthrough) or `none` (no token presented). |
| `issuer_name` | Which configured issuer accepted the token, in a multi-issuer setup. Never the full issuer URL. |
| `inbound_user`, `inbound_groups`, `inbound_uid` | The identity the OIDC token authenticated as. `inbound_uid` appears only when the authenticator supplied one. |
| `inbound_extra` | The impersonation extras the proxy sets itself, from a fixed allowlist. Arbitrary claim data from the token is never logged. |
| `inbound_extra_omitted` | How many extra keys were dropped because they are not on that allowlist, so you can tell data was withheld rather than absent. |
| `outbound_user`, `outbound_groups`, `outbound_uid`, `outbound_extra`, `outbound_extra_omitted` | The same fields for the impersonated identity, present only when the request carried impersonation headers. Compare these with the `inbound_*` fields to see who acted as whom. |
| `target_kind`, `target_name` | On an impersonation denial, what was refused — so a denial never has to be recovered by parsing error text. |

Bearer tokens, `Authorization` and `Cookie` values, request and response bodies,
and arbitrary token claims are never logged. The full list is in
[redaction](./logging.md#redaction).

Two more records close out a request, both INFO:
`request.response.started` (first `WriteHeader` on a long-running request such
as a watch or `exec`, with `time_to_headers_ms`) and
`request.response.completed` (the terminal record for every request, with
`http_status`, `duration_ms`, `response_bytes` and a classified `termination`).
Join them to the access record on `request_id`.

### Watching requests

**Read every replica.** `kubectl logs deploy/<name>` picks one pod. With more
than one replica, a request you just made may have landed on the other one, so
select by label and let kubectl merge the streams:

```bash
kubectl -n kube-oidc-proxy logs -l app.kubernetes.io/name=kube-oidc-proxy \
  --since=10m --tail=-1 --prefix \
  | sed 's/^\[[^]]*\] //' \
  | jq -r 'select(.event_type == "request.access.decided")
           | [.time, .event, .reason // "-", .issuer_name // "-", .http_method, .path] | @tsv'
```

`--prefix` tags each line with its pod, and the `sed` strips that tag so `jq`
sees plain JSON; drop both to keep the pod names. `--tail=-1` lifts the
per-pod line cap kubectl applies when a selector matches several pods.

**One line per request.** A request produces several records: the access
decision, the terminal `request.response.completed` that carries the HTTP
status, and, on a `kubectl --as` request at `-v=1`, one `cache.sar.lookup` per
impersonation header value. Joining them on `request_id` gives one row per
request with the upstream status and the cache outcome attached, which is the
quickest way to tell an authentication problem from an authorization one, and
to see whether the decision cache is doing its job:

```bash
# ~/.zshrc or a file you source
kop-requests() {
  # usage: kop-requests [since] [namespace]   e.g. kop-requests 30m
  kubectl -n "${2:-kube-oidc-proxy}" logs -l app.kubernetes.io/name=kube-oidc-proxy \
      --since="${1:-15m}" --tail=-1 --prefix --max-log-requests=20 \
  | sed -E 's#^\[pod/([^/]+)/[^]]+\] \{#{"pod":"\1",#' \
  | jq -rs '
      map(select(.request_id != null))
      | group_by(.request_id)
      | map(
          (map(select(.event_type == "request.access.decided"))[0] // {}) as $a
          | (map(select(.event_type == "request.response.completed"))[0] // {}) as $r
          # Cache consultations are separate DEBUG records (visible at -v=1),
          # several per request; fold them into one hit/miss/bypass summary.
          | (map(select(.event_type == "cache.sar.lookup" or .event_type == "cache.tokenreview.lookup")
                 | .cache_result)
             | if length == 0 then "-" else
                 (group_by(.) | map("\(.[0]):\(length)") | join(",")) end) as $c
          | select($a.time != null)
          | [ $a.time[11:19], $a.pod[-5:], $a.event, ($a.reason // "-"),
              # The authenticated user, plus who it acted as on a kubectl --as
              # request. Impersonation is the only path the SAR cache serves.
              (($a.inbound_user // "-") + (if $a.outbound_user then " as " + $a.outbound_user else "" end)),
              ($a.issuer_name // "-"),
              # Kubernetes verb and group/resource, as RBAC rules name them. A
              # non-resource path (discovery, /healthz) has neither, so it
              # shows the HTTP method and the path instead.
              ($a.k8s_verb // ($a.http_method | ascii_downcase)),
              (if $a.k8s_resource then
                 (if ($a.k8s_api_group // "") == "" then $a.k8s_resource
                  else $a.k8s_api_group + "/" + $a.k8s_resource end)
               else ($a.path // "-") end),
              ($a.k8s_namespace // "-"),
              $c,
              (($r.http_status // "-") | tostring), (($r.duration_ms // "-") | tostring),
              $a.request_id[0:8] ]
          | @tsv)
      | .[]' \
  | sort \
  | { printf 'TIME\tPOD\tEVENT\tREASON\tUSER\tISSUER\tVERB\tRESOURCE\tNAMESPACE\tCACHE\tSTATUS\tMS\tRID\n'; cat; } \
  | column -t -s $'\t'
}
```

```text
TIME      POD    EVENT      REASON        USER                                             ISSUER                               VERB    RESOURCE                                  NAMESPACE  CACHE   STATUS  MS   RID
17:23:59  l5qhs  AuSuccess  -             gha:my-org/my-repo:refs/heads/main               token.actions.githubusercontent.com  create  authentication.k8s.io/selfsubjectreviews  -          -       403     298  9fd2e1f1
17:44:42  snqkt  AuSuccess  -             gha:my-org/my-repo:refs/heads/main               token.actions.githubusercontent.com  create  authentication.k8s.io/selfsubjectreviews  -          -       201     117  3b1c0a77
17:45:10  l5qhs  AuSuccess  -             google:alice@example.com                         accounts.google.com                  list    apps/deployments                          payments   -       200     88   5c9d2e40
17:45:31  snqkt  AuSuccess  -             gha:my-org/my-repo:refs/heads/main               token.actions.githubusercontent.com  list    secrets                                   default    -       403     61   7e0f1a22
17:52:03  l5qhs  AuFail     unauthorized  -                                                -                                    get     /api/v1/namespaces                        -          -       401     4    a1b2c3d4
17:53:40  snqkt  AuSuccess  -             gha:my-org/my-repo:refs/heads/main as ci-viewer  token.actions.githubusercontent.com  list    namespaces                                -          miss:1  200     93   e5f6a7b8
17:53:43  snqkt  AuSuccess  -             gha:my-org/my-repo:refs/heads/main as ci-viewer  token.actions.githubusercontent.com  list    namespaces                                -          hit:1   200     22   f00dbabe
17:54:12  l5qhs  AuSuccess  -             google:alice@example.com                         accounts.google.com                  get     /apis                                     -          -       200     12   c0ffee00
```

Column notes:

- `EVENT` is the frozen outcome, `AuSuccess` or `AuFail`; every row is a
  `request.access.decided` record, so the event type itself is not repeated.
- `VERB`, `RESOURCE` and `NAMESPACE` are the request-info dimensions the proxy
  resolved (`k8s_verb`, `k8s_api_group`/`k8s_resource`, `k8s_namespace`), in
  the same shape RBAC rules use: the verb is `list`, not `GET`, and the
  resource is `apps/deployments` with the core group left bare. A path with no
  resource behind it, such as discovery, falls back to the HTTP method and the
  path.
- `CACHE` counts the request's cache consultations by result. It is `-` for
  plain token requests, which never touch a cache: the
  [SubjectAccessReview decision cache](./caching.md#subjectaccessreview-decision-cache)
  serves only `kubectl --as` requests and the TokenReview cache only
  passthrough. Those records are DEBUG, so the column is empty below `-v=1`.

How to read it:

- **Row one:** the proxy accepted the token and the API server refused the
  request with 403 before RBAC even applied. When this happens on every request
  from an issuer, the proxy's ServiceAccount is missing an impersonation grant,
  typically a `userextras/<key>` — see the troubleshooting table above.
- **Row two:** the same call after the grant, 201. A working
  `kubectl auth whoami` looks like this from the proxy's side.
- **Row four:** a healthy 403. The identity is fine; the `view` role excludes
  secrets. Authentication succeeded, authorization did not.
- **Row five** never reached the API server. The proxy rejected it and
  `REASON` says why, from the
  [closed vocabulary](./logging.md#reason-vocabularies): an expired token is
  `unauthorized`, with no user or issuer because no identity was established.
  A `kubectl --as` the caller may not perform shows as `impersonation_denied`.
- **Rows six and seven** are the same `kubectl --as ci-viewer` command run
  twice within the allow TTL. The first consulted the cache, missed, and paid
  for a live `SubjectAccessReview`; the second was answered from memory and
  took a quarter of the time.

The `POD` column is the last five characters of the pod name, `RID` the first
eight of the request ID. That prefix is enough to pull every record for one
request, on the proxy and in the API server's audit log where it is the
`auditID`.

**Every record, one per line.** The per-request table hides the records it
joined. This second function shows them: one line per record, with the fixed
columns every record has and a detail column assembled from whichever
meaningful fields the record carries, so an access decision, a cache lookup
and an issuer state change all read without a format per event type. With a
request-ID prefix it traces one request; without, it streams the window.

```bash
# ~/.zshrc or a file you source
kop-events() {
  # usage: kop-events [since] [namespace] [rid-prefix]
  #   kop-events 10m                      every record in the last 10 minutes
  #   kop-events 1h kube-oidc-proxy 9fd2  every record of one request
  kubectl -n "${2:-kube-oidc-proxy}" logs -l app.kubernetes.io/name=kube-oidc-proxy \
      --since="${1:-15m}" --tail=-1 --prefix --max-log-requests=20 \
  | sed -E 's#^\[pod/([^/]+)/[^]]+\] \{#{"pod":"\1",#' \
  | jq -r --arg rid "${3:-}" '
      select($rid == "" or ((.request_id // "") | startswith($rid)))
      | [ (.time[11:19] + "." + (((.time[20:] | gsub("[^0-9]"; "")) + "000")[0:3])),
          (.pod // "-")[-5:], .level, (.component // "-"), (.event_type // "-"),
          ((.request_id // "-")[0:8]),
          # Every meaningful field the record has, as key=value, in this order.
          ([ "event", "reason", "decision", "cache_result", "authenticated",
             "request_coalesced", "target_kind", "target_name",
             "issuer_name", "issuer_state", "pending_reason", "ready_issuers",
             "src_ip", "forwarded_for_untrusted", "auth_method",
             "inbound_user", "outbound_user", "k8s_verb", "k8s_resource", "k8s_namespace",
             "http_status", "duration_ms", "termination", "error_message" ] as $keys
           | . as $rec
           | [ $keys[] | select($rec[.] != null) | "\(.)=\($rec[.] | tostring)" ]
           | if length == 0 then ($rec.msg // "-") else join(" ") end) ]
      | @tsv' \
  | sort \
  | { printf 'TIME\tPOD\tLEVEL\tCOMPONENT\tEVENT_TYPE\tRID\tDETAIL\n'; cat; } \
  | column -t -s $'\t'
}
```

One `kubectl --as ci-viewer get namespaces` at `-v=1`, traced by its prefix:

```text
TIME          POD    LEVEL  COMPONENT  EVENT_TYPE                  RID       DETAIL
17:53:40.000  snqkt  DEBUG  sar        cache.sar.lookup            e5f6a7b8  cache_result=miss
17:53:40.040  snqkt  DEBUG  sar        authz.sar.completed         e5f6a7b8  decision=allow request_coalesced=false target_kind=user duration_ms=41
17:53:40.050  snqkt  INFO   request    request.access.decided      e5f6a7b8  event=AuSuccess decision=allow issuer_name=token.actions.githubusercontent.com src_ip=10.89.165.80 auth_method=oidc inbound_user=gha:my-org/my-repo:refs/heads/main outbound_user=ci-viewer k8s_verb=list k8s_resource=namespaces
17:53:40.090  snqkt  INFO   request    request.response.completed  e5f6a7b8  http_status=200 duration_ms=93 termination=normal
```

Read top to bottom: the cache was consulted and missed, a live
`SubjectAccessReview` took 41 ms and allowed the impersonation, the access
decision recorded who acted as whom from which address, and the upstream
answered 200 in 93 ms end to end. The same command three seconds later shows
`cache_result=hit decision=allow` and no `authz.sar.completed` line at all.

Where the detail fields come from, so you know what to expect on each row:

- `src_ip` and `forwarded_for_untrusted` appear on the access record only.
  `src_ip` is the authoritative client address after the trusted-proxy rules;
  the forwarded chain is shown as the client sent it and is never trusted —
  see [trusted proxies](./configuration.md#trusted-proxies-and-client-ip).
- `cache_result`, `decision`, `duration_ms` and `request_coalesced` come from
  the cache and review records, which are DEBUG and need `-v=1`.
- `issuer_state`, `pending_reason` and `ready_issuers` come from the
  `oidc.issuer.*` lifecycle records, which have no request ID and show up
  only in the window view.
- A record with none of the listed fields falls back to its `msg`.

The full list of fields per record is in the
[logging field reference](./logging.md#field-reference).

**Nothing shows up at all.** Then no request reached the proxy in that window.
An expired token still produces an `AuFail`, so an empty result points at the
path in front of the proxy rather than at the token. Check that anything
arrived, and that the ingress still points at this release's Service:

```bash
kubectl -n kube-oidc-proxy logs -l app.kubernetes.io/name=kube-oidc-proxy --since=10m --tail=-1 \
  | jq -r 'select(.component == "request") | [.time, .event_type, .http_status // "-"] | @tsv'
kubectl -n kube-oidc-proxy get ingress,endpoints -l app.kubernetes.io/name=kube-oidc-proxy
```

Then repeat the request with a tail open in a second terminal, so the record
appears the moment the request arrives:

```bash
kubectl -n kube-oidc-proxy logs -l app.kubernetes.io/name=kube-oidc-proxy -f --tail=0 \
  | jq -c 'select(.component == "request")'
```

**Bypass the network in front.** A port-forward talks to the proxy Service
directly, which separates token, mappings and RBAC from ingress, load balancer
and certificate problems:

```bash
kubectl -n kube-oidc-proxy port-forward svc/kube-oidc-proxy 8443:443 &
kubectl --server=https://127.0.0.1:8443 --insecure-skip-tls-verify=true --token="$TOKEN" auth whoami
kubectl --server=https://127.0.0.1:8443 --insecure-skip-tls-verify=true --token="$TOKEN" get namespaces
```

`auth whoami` prints the identity exactly as the API server saw it: the mapped
username, the groups (plus `system:authenticated`, which the API server adds
itself) and every `extra` value. Add `-v 8` to see the raw status and body
behind kubectl's summary messages.

### Turning up verbosity

`-v` is the single verbosity knob; the chart exposes it as `logging.verbosity`.
At the default `0` every request already produces its access record with the
denial `reason`, so start there. `1` adds DEBUG: the authentication path taken,
cache hits and misses, the live `SubjectAccessReview`, the impersonation header
names. Kubernetes library logging, including the OIDC authenticator's own
detail, is bridged into the same stream at the same verbosity, so `4` and above
surface its token-validation messages too. See
[verbosity](./logging.md#verbosity) for what each level contains.

Persistently, in the values file:

```yaml
logging:
  format: json
  verbosity: "1"
```

Or as a temporary switch that rolls the pods. Pin the chart version you are
running, so a debugging change does not also upgrade the chart:

```bash
helm upgrade kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  --version <x.y.z> -n kube-oidc-proxy -f values.yaml --set logging.verbosity=1
kubectl -n kube-oidc-proxy rollout status deploy/kube-oidc-proxy
kubectl -n kube-oidc-proxy get deploy kube-oidc-proxy \
  -o jsonpath='{.spec.template.spec.containers[0].args}'

# Back to the default when done: the same command without the override.
helm upgrade kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  --version <x.y.z> -n kube-oidc-proxy -f values.yaml
```

Then read the DEBUG records around an access record, and anything the
Kubernetes libraries said:

```bash
kubectl -n kube-oidc-proxy logs -l app.kubernetes.io/name=kube-oidc-proxy --since=10m --tail=-1 \
  | jq -r 'select(.level == "DEBUG" or .component == "k8s")
           | [.time, .level, .component, .event_type // "-", .msg] | @tsv'
```

Issuer state, in case a JWKS fetch is the problem rather than the token:

```bash
kubectl -n kube-oidc-proxy logs -l app.kubernetes.io/name=kube-oidc-proxy --tail=-1 \
  | jq -r 'select(.event_type | startswith("oidc.issuer."))
           | [.time, .event_type, .issuer_name, .issuer_state // "-", .pending_reason // "-"] | @tsv'
```

`--logging-format=text` is easier on the eye while debugging interactively;
switch back to `json` before leaving it, since that is what log pipelines
expect.

## Upgrade and rollback

The proxy is stateless: every replica holds only what it fetched at startup
(issuer discovery documents and signing keys) and short-lived review caches.
An upgrade is therefore a rolling replacement, and a rollback is the same
thing in the other direction. What needs care is around the edges.

**Before.** Read the release notes for the versions you are crossing, with an
eye on two contracts: chart values that changed meaning or default, and the
[log compatibility rules](./logging.md#compatibility), so a saved query or
alert is adjusted before, not after, the records change. Pin what you deploy:

```sh
helm show chart oci://ghcr.io/rafpe/charts/kube-oidc-proxy --version <x.y.z> | grep -E '^(version|appVersion):'
```

The chart's default image tag follows its `appVersion`, so pinning the chart
version pins the image; set `image.tag` only to diverge on purpose.

**During.** Upgrade with the values file, never `--reuse-values`, so that
defaults added by the new chart apply:

```sh
helm upgrade kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  --version <x.y.z> -n kube-oidc-proxy -f values.yaml
kubectl -n kube-oidc-proxy rollout status deploy/kube-oidc-proxy
```

With two or more replicas and the chart's PodDisruptionBudget enabled, the
rollout keeps a replica serving throughout. Each new pod becomes ready once
its first issuer's JWKS has loaded (or all of them, with
`readinessRequireAllIssuers`), so a rollout is also a check that every issuer
is still reachable from the cluster.

**After.** Two smoke tests, with a real token, prove identity and
authorization survived the upgrade:

```sh
kubectl --server=https://<proxy> --token="$TOKEN" auth whoami          # the mapped identity, unchanged
kubectl --server=https://<proxy> --token="$TOKEN" auth can-i --list     # the same permissions as before
```

Then confirm the new pods log the expected issuers as initialized and that
the [request viewer](#watching-requests) shows `AuSuccess` rows with the
upstream status you expect.

**Rollback.** `helm rollback kube-oidc-proxy <revision> -n kube-oidc-proxy`
restores the previous chart and values together; find the revision with
`helm history`. Because the proxy holds no state, that is the whole procedure.
The one thing Helm does not restore is anything you manage outside the chart:
a ConfigMap holding an audit policy, a TLS Secret, RBAC bindings for mapped
identities. Keep those in the same Git history as the values file so a
rollback is one revert.

## Availability and issuer outages

Readiness describes the moment a pod starts serving; this section is about
what happens afterwards, when an identity provider is slow, unreachable, or
rotates its keys.

- **At startup**, each issuer's discovery document and JWKS are fetched, with
  retries. An issuer that cannot be reached stays *pending* and its tokens
  fail with 401 until it initializes; other issuers are unaffected. By
  default the pod is ready as soon as one issuer has initialized, so a
  provider outage during a rollout does not block the other providers.
  Readiness latches: once ready, a pod does not report unready again because
  an issuer later fails.
- **After startup, with the issuer unreachable**, tokens signed by keys the
  proxy already holds keep verifying. Signature verification is local against
  the cached JWKS; no request is made to the issuer for a token whose key ID
  is known. Existing users and pipelines therefore keep working through an
  identity-provider outage, for as long as their tokens are valid and the
  provider does not rotate its keys.
- **Key rotation during an outage** is the failure case. A token signed with
  a key ID the proxy has not seen triggers a JWKS refresh; concurrent requests
  for the same unknown key share one fetch. If the issuer cannot be reached,
  that verification fails with 401 until it can. Providers rotate on schedules
  of days to weeks, so this window is narrow but real; it is the reason to
  alert on `authn.oidc.failed` rate rather than on issuer reachability alone.
- **A replica restart during an outage** brings the startup rules back: the
  new pod must fetch discovery and JWKS afresh, so it cannot initialize the
  unreachable issuer and, with `readinessRequireAllIssuers: true`, does not
  become ready at all. This is the argument for the default `false` on
  clusters with more than one identity provider, and for a
  PodDisruptionBudget: it stops voluntary disruption from replacing every
  pod during an outage.
- **Long-running requests** (`watch`, `logs -f`, `exec`) are held open by the
  proxy for as long as the client keeps them; a pod being terminated drains
  them within the termination grace period. Nothing about an issuer outage
  cuts an established connection, since the token was verified when it was
  opened.

To see the state of each issuer in each pod at any time, use the
[issuer state query](./logging.md#issuer-state).

**A layout that survives the above.** The chart ships single-replica by
default. For production, run more than one replica and keep them spread and
protected during disruptions:

```yaml
replicaCount: 3
podDisruptionBudget:
  enabled: true
  minAvailable: 2
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: kube-oidc-proxy
readinessRequireAllIssuers: false   # the default; stated here on purpose
```

The PodDisruptionBudget keeps node drains from taking every replica at once,
which is exactly the moment a restart during an issuer outage would hurt;
topology spread puts the replicas in different zones; and the readiness
default means one provider's outage never blocks a rollout for the others.

## Capacity and sizing

There are no published baselines, because the numbers depend on your traffic
shape more than on the proxy: a cluster whose only clients are pipelines
running `kubectl apply` a few hundred times a day and one with fifty
engineers holding `watch` streams open all day are different workloads. The
chart deliberately ships `resources: {}`. What follows is how to measure,
not what to set.

**What costs what.** A request costs one signature verification (CPU, cheap)
plus a proxied round trip; nothing is buffered, so memory per request is
small and bounded. The exceptions are the streams: every open `watch`,
`exec`, `portforward` or `logs -f` holds a connection and a goroutine for
its whole life, so concurrent long-running requests, not requests per second,
are the memory dimension. Review traffic is separate: `kubectl --as` costs
one `SubjectAccessReview` per impersonation header value, and passthrough
costs a `TokenReview`, both against the API server and both cached for a
short TTL ([caching](./caching.md)). Log volume is at least two records per
request at the default verbosity and several more at `-v=1`.

**How to measure.** Run with requests set and no limits for a representative
period, then read what the pods actually used:

```sh
kubectl -n kube-oidc-proxy top pod -l app.kubernetes.io/name=kube-oidc-proxy
```

together with the request rate and the number of open streams from the log:

```sh
# requests per minute over the window
kubectl -n kube-oidc-proxy logs -l app.kubernetes.io/name=kube-oidc-proxy --since=1h --tail=-1 \
  | jq -r 'select(.event_type == "request.response.completed") | .time[0:16]' | sort | uniq -c
# how many requests were long-running streams
kubectl -n kube-oidc-proxy logs -l app.kubernetes.io/name=kube-oidc-proxy --since=1h --tail=-1 \
  | jq -r 'select(.event_type == "request.response.started") | .request_id' | wc -l
```

Set requests to the observed steady state with headroom for the streams you
expect at peak, and a memory limit well above it; a CPU limit is rarely
useful for a proxy and can only add latency. Two replicas is the floor for
availability; add replicas for open-stream capacity, not for request rate,
which a single replica handles comfortably at the scale of a cluster's
kubectl traffic.

## See also

- [Getting started](./getting-started.md) — the install this page assumes.
- [Logging reference](./logging.md) — every record and field the queries here
  use.
- [Auditing](./auditing.md) — the audit trail next to the log.
- [Caching and API-server protection](./caching.md) — the TTLs behind the
  revocation lag.
- [Development](./development.md) — building, testing and the local kind
  walkthrough.
- [Architecture](./architecture.md) — request flow and readiness.
