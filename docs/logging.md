# Logging

`kube-oidc-proxy` writes one structured stream. Every first-party record is a
single JSON object on stdout — startup, readiness, per-request access
decisions, cache lookups, shutdown — encoded by `log/slog` and carrying the
same envelope. There is no second text log to collect and no separate access-log
file: `--logging-format` picks the encoding for the whole stream and `-v` picks
how much of it you see.

- [Record shape](#record-shape)
- [Rules](#rules)
- [Verbosity](#verbosity)
- [Event registry](#event-registry)
- [Field reference](#field-reference)
- [Shutdown and exit status](#shutdown-and-exit-status)
- [Correlation](#correlation)
- [Worked queries](#worked-queries)
- [ECS mapping](#ecs-mapping)
- [Versioning](#versioning)
- [Redaction](#redaction)

## Record shape

Every record the proxy emits itself carries the same six keys before any
event-specific field:

| Field | Type | Values / format | Notes |
| --- | --- | --- | --- |
| `time` | string | RFC 3339 with sub-second precision | `slog` default |
| `level` | string | `ERROR`, `WARN`, `INFO`, `DEBUG` | `slog` default |
| `msg` | string | static text per event, never interpolated | query on `event_type`, not `msg` |
| `schema_version` | int | `1` | bumped only on a breaking field change |
| `component` | string | `startup`, `server`, `oidc`, `readiness`, `request`, `tokenreview`, `sar`, `audit`, `upstream`, `shutdown`, `k8s` | which subsystem spoke; `k8s` marks bridged library output |
| `event_type` | string | `<domain>.<object>.<action>`, one of the 40 registered values | absent on `component=k8s` records |

An access decision looks like this (line-wrapped here, one line in the stream):

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

Records bridged from the Kubernetes libraries (client-go, apimachinery, the
apiserver filters) carry `component=k8s` and **no** `event_type`. That absence
is the filter: `event_type` present means the proxy said it, `component=k8s`
means a library did.

## Rules

Five rules govern the event set. They are what makes a saved query keep working
across upgrades.

1. **Append-only.** New `event_type` values may be added in any release. An
   existing value is never repurposed and never renamed in place; a retired
   value keeps its constant so the string is never reused.
2. **Adding a value does not bump `schema_version`.** A query that matches one
   value is unaffected by the existence of a new one, so a new event is not a
   breaking change. `schema_version` moves only when field parsing breaks.
3. **The registry is the source.** `pkg/logging/events.go` holds one entry per
   event with its component, default level, mandatory fields and one-line
   summary. The table below is generated from it by `make eventdoc`; CI fails
   on a diff. Never hand-edit between the `events:begin` and `events:end`
   markers.
4. **Query on `event_type`, not `msg`.** `msg` is static human text and may be
   reworded. `event_type` is the machine contract.
5. **`component=k8s` records have no `event_type`.** They come from Kubernetes
   libraries through the klog bridge, keep their own wording, and are excluded
   from every rule above.

## Verbosity

`-v` is the single verbosity knob. There is no independent `--log-level`.

| Level | Content | Visible at |
| --- | --- | --- |
| ERROR | The process cannot serve correctly: audit backend start or flush failure, the API server unreachable for a `SubjectAccessReview` or `TokenReview`, an internal invariant breach, an unreadable CA. | always |
| WARN | Degraded state and anomalies: an issuer pending with a reason (on state change only), a forwarded header dropped, repeated reserved-identity attempts, header-cap attempts. | always |
| INFO | Lifecycle (effective config and version, issuer configured and initialized, ready, serving, shutdown milestones, hook results) and the access record for every request, unsampled. | `-v=0` |
| DEBUG | Per-request internals: the auth path taken, cache hit or miss, the live `SubjectAccessReview`, impersonation header names, client cancellation. | `-v>=1` |

WARN and ERROR are never hidden, whatever `-v` says. Denials are INFO on the
access record and are never rate-limited: a bad token must not be able to buy a
warning line, and denial *rates* belong in metrics. Only
`request.anomaly.detected`, `request.headers.dropped` and
`log.warning.suppressed` are token-bucketed; when the bucket drops records,
`log.warning.suppressed` reports `warning_reason`, `suppressed_count` and
`interval_seconds`.

`--logging-format` selects `json` (the default) or `text` for the whole stream.
Both flags are documented in the
[configuration reference](./configuration.md#logging).

## Event registry

40 registered values, generated from the registry. "Required" lists the fields
that must be present beyond `time`, `level`, `msg`, `schema_version`,
`component` and `event_type`; conditional fields are described in the summary.

<!-- events:begin -->
| `event_type` | components | level | required | summary |
|---|---|---|---|---|
| `audit.backend.failed` | `audit` | ERROR | `error_message` | The audit backend did not start. |
| `audit.backend.started` | `audit` | INFO | `backend_kind` | The audit backend is running. |
| `audit.flush.completed` | `audit` | INFO | `duration_ms` | The pre-shutdown audit flush succeeded. |
| `audit.flush.failed` | `audit` | ERROR | `error_message` | The pre-shutdown audit flush failed. |
| `authn.oidc.failed` | `oidc` | DEBUG | `request_id`, `reason` | The OIDC authenticator rejected the token. The denial itself is INFO on request.access.decided. |
| `authn.oidc.succeeded` | `oidc` | DEBUG | `request_id`, `issuer_name` | The OIDC authenticator accepted the token. Names the issuer that accepted it. |
| `authn.token.missing` | `tokenreview` | DEBUG | `request_id` | No bearer token was presented on the TokenReview path. |
| `authn.tokenreview.completed` | `tokenreview` | DEBUG | `request_id`, `authenticated` | A live TokenReview answered, with duration_ms. A cache hit is reported by cache.tokenreview.lookup instead. |
| `authn.tokenreview.failed` | `tokenreview` | ERROR | `request_id`, `reason`, `error_message` | The API server was unreachable or returned a status error. Carries reason=authentication_dependency_error. |
| `authz.impersonation.resolved` | `sar` | DEBUG | `request_id`, `target_kind`, `target_name` | The whole impersonation sequence was allowed. A denial is request.access.decided with decision=deny and reason=impersonation_denied. |
| `authz.sar.completed` | `sar` | DEBUG | `request_id`, `decision`, `duration_ms`, `request_coalesced`, `target_kind` | A live or shared SubjectAccessReview returned. Fires once per impersonation header value, so one request can emit several. |
| `authz.sar.failed` | `sar` | ERROR or DEBUG | `request_id`, `reason`, `error_message` | The SubjectAccessReview call failed. Carries reason=authorization_dependency_error, or reason=client_canceled at DEBUG when the client hung up before the review answered. |
| `cache.sar.lookup` | `sar` | DEBUG | `request_id`, `cache_result` | One SubjectAccessReview cache consultation. Carries decision on a hit, never the cache key. |
| `cache.tokenreview.lookup` | `tokenreview` | DEBUG | `request_id`, `cache_result` | One TokenReview cache consultation. Carries authenticated on a hit, never the cache key. |
| `log.warning.suppressed` | any | WARN | `warning_reason`, `suppressed_count`, `interval_seconds` | Token-bucket summary of dropped warning records. |
| `oidc.issuer.configured` | `oidc` | INFO | `issuer_name`, `issuer_count` | Once per configured issuer at startup. |
| `oidc.issuer.initialized` | `oidc` | INFO | `issuer_name`, `issuer_state`, `ready_issuers`, `total_issuers` | An issuer's JWKS loaded. Carries issuer_state=initialized. |
| `oidc.issuer.pending` | `oidc` | WARN | `issuer_name`, `issuer_state`, `pending_reason`, `ready_issuers`, `total_issuers` | The pending set or a pending reason changed. Carries issuer_state=pending; not emitted on every scrape. |
| `proxy.config.invalid` | `startup` | ERROR | `reason`, `error_message` | The configuration cannot be used, including a CA bundle that cannot be read. |
| `proxy.config.loaded` | `startup` | INFO | `version`, `config_hash`, `issuer_count`, `readiness_mode` | The effective non-secret configuration is fixed. |
| `proxy.hook.completed` | `shutdown` | INFO | `hook`, `duration_ms` | One record per pre-shutdown hook that finished. |
| `proxy.hook.failed` | `shutdown` | ERROR | `hook`, `error_message` | A pre-shutdown hook returned an error. |
| `proxy.server.started` | `server` | INFO | `address` | The secure listener is serving. |
| `proxy.server.stopped` | `server` | INFO | `duration_ms` | The secure listener stopped. |
| `proxy.shutdown.completed` | `shutdown` | INFO | `duration_ms` | Listeners stopped, readiness stopped and pre-shutdown hooks finished. |
| `proxy.shutdown.started` | `shutdown` | INFO | `signal` | A termination signal was received. The forced exit is the same event with forced=true. |
| `proxy.startup.failed` | `startup` | ERROR | `error_message` | The process could not reach serving after the logger was built; it exits non-zero without a second, unstructured error line. |
| `readiness.proxy.ready` | `readiness` | INFO | `ready_issuers`, `total_issuers`, `readiness_mode` | Readiness latched to ready. |
| `readiness.server.failed` | `readiness` | ERROR | `error_message` | The readiness HTTP server returned an error. |
| `request.access.decided` | `request` | INFO | `request_id`, `event`, `src_ip`, `path`, `http_method`, `auth_method`, `decision` | Authentication, authorization and proxy admission decided for a request. Carries event=AuSuccess\|AuFail. |
| `request.anomaly.detected` | `request` | WARN | `request_id`, `src_ip`, `reason` | A rejection that indicates an exploit attempt or gross misconfiguration. Token-bucketed; the access record still carries the outcome. |
| `request.handler.failed` | `request` | ERROR | `request_id`, `reason`, `error_message` | The proxy hit an internal error while handling a request; the access record carries reason=internal_error. |
| `request.headers.dropped` | `request` | WARN | `request_id`, `src_ip`, `dropped_headers` | X-Forwarded-For or X-Real-Ip removed for an untrusted peer, a fully trusted chain or a malformed hop. Carries forwarded_for_untrusted when the client sent an X-Forwarded-For; a client that sent only X-Real-Ip has no chain to report. Token-bucketed. |
| `request.headers.rewritten` | `request` | DEBUG | `request_id`, `src_ip`, `forwarded_for_untrusted` | X-Forwarded-For collapsed to the resolved client IP on the trusted-proxy path. Diagnostic, not a warning: it is the trusted-proxy contract working as configured and fires on every request behind a trusted ingress. |
| `request.impersonation.applied` | `request` | DEBUG | `request_id`, `outbound_user`, `impersonated_header_names` | Outbound impersonation headers built. Header names only, never values. |
| `request.impersonation.skipped` | `request` | DEBUG | `request_id`, `skip_reason` | Impersonation was disabled by flag, or the request took the TokenReview passthrough path. |
| `request.response.completed` | `request` | INFO | `request_id`, `http_status`, `duration_ms`, `termination` | The handler returned. The terminal record for every request, mirroring the audit stage ResponseComplete. |
| `request.response.started` | `request` | INFO | `request_id`, `http_status`, `time_to_headers_ms` | First WriteHeader on a long-running request. Mirrors the audit stage ResponseStarted. |
| `upstream.request.canceled` | `upstream` | DEBUG | `request_id`, `reason` | The client went away before the upstream response completed. Carries reason=client_canceled. |
| `upstream.request.failed` | `upstream` | ERROR or DEBUG | `request_id`, `reason`, `termination`, `error_message` | The reverse proxy transport failed. Carries reason=upstream_error and a classified termination; drops to DEBUG when the client canceled the request. |
<!-- events:end -->

## Field reference

Status: **frozen** means the name and value format exist today and must not
change — SIEM rules key on them. **new** means added by the structured-logging
work.

`src_ip` and `path` are the only emitted names for the client address and the
request path. No alias of either is emitted and no deprecation window is open.
If an alias is ever added it goes in this table with a status of `alias`.

### On request-scoped records

| Field | Type | Values / format | Status | Records | Notes |
| --- | --- | --- | --- | --- | --- |
| `request_id` | string | UUID v4 minted by the proxy, max 64 chars | new | all request records | the same value as the `Audit-ID` header sent upstream and echoed to the client |
| `client_request_id` | string | inbound `Audit-ID` or `X-Request-ID`, printable ASCII, max 64 chars | new | `request.access.decided` | present only when a valid inbound value existed; never used as `request_id` unless the peer is a trusted proxy |
| `event` | string | `AuSuccess`, `AuFail` | frozen | `request.access.decided` | the SIEM contract |
| `src_ip` | string | IPv4 or IPv6, trusted-proxy resolved | frozen | all request records | the raw peer address with its port is never logged |
| `forwarded_for_untrusted` | string | raw `X-Forwarded-For` chain, sanitized | frozen | `request.access.decided`, `request.headers.*` | forensic, not identity |
| `path` | string | URL path, query string stripped, sanitized | frozen | `request.access.decided` | |
| `http_method` | string | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, `CONNECT` | new | `request.access.decided` | |
| `k8s_verb` | string | `get`, `list`, `watch`, `create`, `update`, `patch`, `delete`, `deletecollection`, `proxy`, `connect` | new | `request.access.decided` | from the request-info resolver; absent on non-resource paths |
| `k8s_api_group` | string | API group, empty string for the core group | new | `request.access.decided` | |
| `k8s_resource` | string | resource name, for example `pods` | new | `request.access.decided` | |
| `k8s_subresource` | string | for example `exec`, `log`, `portforward` | new | `request.access.decided` | absent when none |
| `k8s_namespace` | string | namespace | new | `request.access.decided` | absent for cluster-scoped requests |
| `k8s_name` | string | object name, max 256 chars | new | `request.access.decided` | absent on list and watch |
| `auth_method` | string | `oidc`, `tokenreview`, `none` | new | `request.access.decided` | `none` is the no-token 401 path |
| `issuer_name` | string | configured issuer name, max 256 chars | new | `request.access.decided`, `oidc.issuer.*` | never the full issuer URL |
| `reason` | string | closed set, see [reason vocabularies](#reason-vocabularies) | new | `request.access.decided` on `AuFail`, and on error records | |
| `decision` | string | `allow`, `deny` | new | `request.access.decided`, `cache.sar.lookup`, `authz.sar.completed` | authorization outcome |
| `inbound_user` | string | username, sanitized, max 256 chars | frozen | `request.access.decided` | |
| `inbound_uid` | string | UID, sanitized | frozen | `request.access.decided` | absent when empty |
| `inbound_groups` | array of string | first 32 groups, sanitized | frozen | `request.access.decided` | the cap is new |
| `inbound_groups_omitted` | int | groups beyond the cap | new | `request.access.decided` | absent when zero |
| `inbound_extra` | object | allowlisted impersonation extras only | frozen | `request.access.decided` | `originaluser.jetstack.io-extra` is no longer on the allowlist |
| `inbound_extra_omitted` | int | count of extras not logged | frozen | `request.access.decided` | |
| `outbound_user`, `outbound_uid`, `outbound_groups`, `outbound_groups_omitted`, `outbound_extra`, `outbound_extra_omitted` | as the `inbound_*` fields | as the `inbound_*` fields | frozen (the caps are new) | `request.access.decided` when impersonating | compare with `inbound_*` to see who acted as whom |
| `target_kind` | string | `user`, `group`, `uid`, `extra`, `serviceaccount`, `unknown` | new | `request.access.decided` on `impersonation_denied`, `authz.sar.completed`, `authz.impersonation.resolved` | replaces parsing the error text |
| `target_name` | string | impersonation target, sanitized, max 256 chars | new | same as `target_kind` | |
| `http_status` | int | HTTP status written to the client | new | `request.response.started`, `request.response.completed` | a `200` implied by the first `Write`, or by a handler that returned without writing, is recorded as `200`; `0` only when no response went out, because the connection was hijacked or the handler aborted before writing |
| `time_to_headers_ms` | int | milliseconds from request start to `WriteHeader` | new | `request.response.started` | long-running requests only |
| `duration_ms` | int | milliseconds from request start to handler return | new | `request.response.completed`, `authz.sar.completed`, `authn.tokenreview.completed` | |
| `response_bytes` | int | bytes written to the client | new | `request.response.completed` | absent when the connection was hijacked |
| `termination` | string | `normal`, `client_cancel`, `upstream_reset`, `upstream_timeout`, `proxy_error`, `hijacked`, `panic` | new | `request.response.completed`, `upstream.request.failed` | |
| `error_message` | string | sanitized, max 512 chars | new | DEBUG records, ERROR records and `internal_error` | never at INFO or WARN for a client-caused failure |
| `dropped_headers` | array of string | `x-forwarded-for`, `x-real-ip` | new | `request.headers.dropped` | |
| `skip_reason` | string | `disabled`, `passthrough` | new | `request.impersonation.skipped` | |
| `impersonated_header_names` | array of string | `Impersonate-User`, `Impersonate-Group`, `Impersonate-Uid`, `Impersonate-Extra-<key>` | new | `request.impersonation.applied` | header names only, never values |

### On cache and review records

| Field | Type | Values / format | Records | Notes |
| --- | --- | --- | --- | --- |
| `cache_result` | string | `hit`, `miss`, `bypass` | `cache.sar.lookup`, `cache.tokenreview.lookup` | `bypass` covers a disabled cache and an oversized SAR spec; `miss` includes expired |
| `request_coalesced` | bool | `true`, `false` | `authz.sar.completed` | singleflight shared one live check between requests |
| `decision` | string | `allow`, `deny` | `cache.sar.lookup`, `authz.sar.completed` | on a SAR cache hit |
| `authenticated` | bool | `true`, `false` | `authn.tokenreview.completed`, `cache.tokenreview.lookup` | on a TokenReview cache hit |
| `duration_ms` | int | live call duration | `authz.sar.completed`, `authn.tokenreview.completed` | absent on a cache hit |

Cache keys, token hashes and the serialized `SubjectAccessReview` spec are never
logged. The cache identity is in the event type, not in a field.

### On lifecycle records

| Field | Type | Values / format | Records |
| --- | --- | --- | --- |
| `version` | string | build version | `proxy.config.loaded` |
| `config_hash` | string | hash of the effective non-secret configuration | `proxy.config.loaded` |
| `issuer_count` | int | configured issuers | `proxy.config.loaded`, `oidc.issuer.configured` |
| `issuer_state` | string | `pending`, `initialized` | `oidc.issuer.initialized`, `oidc.issuer.pending` |
| `pending_reason` | string | `not_initialized`, `transient`, `error` | `oidc.issuer.pending` |
| `ready_issuers`, `total_issuers` | int | counts | `oidc.issuer.initialized`, `oidc.issuer.pending`, `readiness.proxy.ready` |
| `readiness_mode` | string | `any`, `all` | `proxy.config.loaded`, `readiness.proxy.ready` |
| `hook` | string | pre-shutdown hook name | `proxy.hook.completed`, `proxy.hook.failed` |
| `warning_reason` | string | the suppressed record's `reason` | `log.warning.suppressed` |
| `suppressed_count` | int | records dropped in the interval | `log.warning.suppressed` |
| `interval_seconds` | int | summary interval | `log.warning.suppressed` |
| `address` | string | bound listen address | `proxy.server.started` |
| `signal` | string | `SIGTERM`, `SIGINT` | `proxy.shutdown.started` |
| `forced` | bool | `true` on the final signal | `proxy.shutdown.started`, absent otherwise |
| `backend_kind` | string | audit backend type | `audit.backend.started` |

### Reason vocabularies

`reason` is a closed set, but there are two of them and they never mix.

**Request failures** — on `request.access.decided` with `event=AuFail`, on
`request.response.completed` when the request ended in an error, and on the
`authn.*`, `authz.*`, `upstream.*` and `request.handler.failed` records:

`unauthorized`, `reserved_identity`, `impersonation_denied`,
`too_many_impersonation_values`, `no_username_claim`,
`authentication_dependency_error`, `authorization_dependency_error`,
`upstream_error`, `internal_error`, `client_canceled`.

**Startup configuration failures** — on `proxy.config.invalid` only, a
startup-scoped vocabulary that is deliberately disjoint from the request set so
a query for a configuration problem can never match request traffic:

`ca_file_unreadable`, `invalid_configuration`.

`ca_file_unreadable` is emitted when the CA bundle named by
`--oidc-ca-file` cannot be read; `invalid_configuration` is reserved for an
effective configuration the process refuses.

### Values explicitly excluded

Bearer tokens, `Authorization` and `Cookie` values, any header not on the
allowlist, request and response bodies, cache keys, arbitrary claims and
extras, configured extra-header values, the `User-Agent` header, full issuer
URLs, and raw peer addresses with ports.

## Startup, shutdown and exit status

The log stream is the only place the process reports its own failures once the
root logger exists. A startup error after that point (an unreadable kubeconfig,
a certificate that does not load, a port already bound) emits
`proxy.startup.failed` with `error_message` and the process exits `1` without
printing a second, unstructured line. Only a failure before the logger can be
built, such as an unknown flag or an invalid `--logging-format`, is printed to
stderr as plain text, because there is nothing else to report through yet.

`audit.Shutdown` flushes the audit backend and **returns** the backend's error
rather than swallowing it. It is registered as the `AuditBackend` pre-shutdown
hook, so a flush the backend reports as failed emits `audit.flush.failed`,
propagates out of `RunPreShutdownHooks` as `proxy.hook.failed`, and makes the
process **exit non-zero**. A dropped audit event for a request this process
already served is not a warning to be tidied away.

The backends bundled from `k8s.io/apiserver` (`log`, and the buffered `webhook`)
do not report an error from `Shutdown()`: the upstream `audit.Backend` interface
has no return value there, and the buffered backend logs a delivery failure
through the Kubernetes error handler instead. With those backends a lost flush
is visible as a bridged `component=k8s` ERROR record, `audit.flush.completed`
still follows with `duration_ms`, and the process exits `0`. The non-zero exit
applies to a backend that implements the optional `ShutdownErr() error`
extension, which none of the bundled ones do today.

## Correlation

One request produces several records — an access decision, cache lookups, a
`SubjectAccessReview`, a terminal `request.response.completed`. `request_id`
joins them, and it reaches beyond this process:

- The outermost filter mints a UUID v4 per request and sets it as the
  **`Audit-ID` request header**.
- Both proxy audit chains read that header, so the proxy's own audit events
  carry the same value instead of minting two.
- The reverse proxy forwards the header upstream, so the **kube-apiserver audit
  event's `auditID` is the same string**. One id spans the proxy log, the proxy
  audit log and the API server audit log.
- The response carries `Audit-ID` back to the client, so a user can quote the id
  of the request they are complaining about.

In short: **`request_id` = the `Audit-ID` header = the kube-apiserver
`auditID`.**

An inbound `Audit-ID` or `X-Request-ID` is **not** adopted as `request_id`
unless the immediate peer is inside a configured `--trusted-proxies` network. A
syntactically valid inbound value from an untrusted peer is kept as
`client_request_id` on the access record — visible for correlation with an
ingress, never authoritative. See
[trusted proxies and client IP](./configuration.md#trusted-proxies-and-client-ip).

Two vocabularies differ between the proxy and the API server, on purpose:

| Proxy | kube-apiserver audit | Meaning |
| --- | --- | --- |
| `decision=allow` | `authorization.k8s.io/decision=allow` | the request was authorized |
| `decision=deny` | `authorization.k8s.io/decision=forbid` | the request was refused |

**`decision=deny` equals `authorization.k8s.io/decision=forbid`.** The proxy
keeps `deny` because `event=AuSuccess|AuFail` and `decision=allow|deny` are the
frozen contract SIEM rules already key on. `event` names the outcome,
`event_type` names the record shape; `AuSuccess` is only ever emitted with
`decision=allow` and `AuFail` only with `decision=deny`, and a test enforces the
pairing.

## Worked queries

Three questions, in three query languages. `$POD` is a proxy pod, `$RID` a
request id.

### Everything for one request

```bash
kubectl -n kube-oidc-proxy logs "$POD" | grep "\"request_id\":\"$RID\""
```

```logql
{app="kube-oidc-proxy"} | json | request_id = "<request-id>"
```

```splunk
index=kubernetes sourcetype=kube-oidc-proxy request_id="<request-id>"
| sort 0 _time
| table _time level event_type decision reason http_status duration_ms
```

The same id in the API server audit log finds the upstream half:
`auditID == "<request-id>"`.

### Denials by reason in the last hour

```bash
kubectl -n kube-oidc-proxy logs "$POD" --since=1h \
  | jq -r 'select(.event_type == "request.access.decided" and .decision == "deny") | .reason' \
  | sort | uniq -c | sort -rn
```

```logql
sum by (reason) (
  count_over_time(
    {app="kube-oidc-proxy"} | json
      | event_type = "request.access.decided" | decision = "deny" [1h]
  )
)
```

```splunk
index=kubernetes sourcetype=kube-oidc-proxy earliest=-1h
  event_type="request.access.decided" decision="deny"
| stats count by reason
| sort -count
```

### Issuer pending

```bash
kubectl -n kube-oidc-proxy logs "$POD" \
  | jq -r 'select(.event_type == "oidc.issuer.pending")
           | "\(.issuer_name)\t\(.pending_reason)\t\(.ready_issuers)/\(.total_issuers)"'
```

```logql
{app="kube-oidc-proxy"} | json | event_type = "oidc.issuer.pending"
  | line_format "{{.issuer_name}} {{.pending_reason}} {{.ready_issuers}}/{{.total_issuers}}"
```

```splunk
index=kubernetes sourcetype=kube-oidc-proxy event_type="oidc.issuer.pending"
| stats latest(pending_reason) AS pending_reason latest(_time) AS last_seen by issuer_name
```

`oidc.issuer.pending` fires on a state change, not on every readiness scrape, so
the newest record per `issuer_name` is the current state. See
[multi-issuer readiness](./multi-issuer.md#readiness).

## ECS mapping

The proxy's field names are the contract; they are **not** renamed to
[Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html).
This table is for whoever writes the ingest pipeline that copies them.

| Proxy field | ECS field | Notes |
| --- | --- | --- |
| `time` | `@timestamp` | |
| `level` | `log.level` | |
| `msg` | `message` | |
| `component` | `log.logger` | |
| `event_type` | `event.action` | |
| `request_id` | `trace.id` | also the kube-apiserver `auditID`; `http.request.id` if you prefer a transaction-scoped field |
| `src_ip` | `source.ip` | the resolved client IP |
| `path` | `url.path` | |
| `http_method` | `http.request.method` | |
| `http_status` | `http.response.status_code` | |
| `response_bytes` | `http.response.body.bytes` | |
| `duration_ms` | `event.duration` | **`event.duration` is nanoseconds** — multiply by 1,000,000 |
| `time_to_headers_ms` | — | no ECS equivalent; keep as a custom field |
| `event` | `event.outcome` | `AuSuccess` → `success`, `AuFail` → `failure`; ECS also allows `unknown`. Map from `event`, not from `decision` |
| `reason` | `event.reason` | |
| `inbound_user` | `user.name` | the authenticated identity |
| `inbound_groups` | `user.roles` | |
| `outbound_user` | `user.effective.name` | ECS's `user.effective.*` reusable set is exactly the impersonation case |
| `outbound_groups` | `user.effective.roles` | |
| `error_message` | `error.message` | |
| `k8s_verb`, `k8s_resource`, `k8s_namespace`, … | — | no ECS equivalent; keep as custom fields under your own namespace |

## Versioning

- **Adding an `event_type` value** is allowed in any release and does not bump
  `schema_version`. A query for one value is unaffected by a new one.
- **Renaming a value after it has shipped is breaking.** A record carries one
  `event_type`, so there is no overlap window and emitting both names
  double-counts. The recovery is: add the new value, stop the old one in the
  same release, keep the old constant marked retired so the string is never
  reused, publish an `event_type IN (old, new)` migration query, and announce it
  in the changelog. At least one minor release of notice, one major for anything
  under `request.*` or `authn.*`.
- **Retiring a value because its code path was removed is not breaking.**
  Queries return nothing instead of failing. Keep the constant marked retired.
- **`schema_version` bumps only when field parsing breaks**: a field removed or
  retyped, or a closed value set narrowed. Not for a new event, a new optional
  field, or a widened value set.

`request.handler.failed` (component `request`, ERROR) and
`proxy.startup.failed` (component `startup`, ERROR) were added to the registry
during implementation, before the first release that ships `event_type`, under
the append-only rule. They bring the set to 40. Because nothing had shipped, no
consumer needed a migration; a value added after the first release follows the
rules above instead.

## Redaction

- Never logged: bearer tokens, `Authorization` and `Cookie` values, any header
  not on the allowlist, request and response bodies, cache keys, arbitrary
  claims and extras, configured extra-header values, the `User-Agent` header,
  full issuer URLs.
- `originaluser.jetstack.io-extra` is not on the loggable extras allowlist. That
  extras existed is reported as a bounded count (`inbound_extra_omitted`,
  `outbound_extra_omitted`), never as content.
- Every user-influenced string passes through the `sanitize` helper, which
  strips control characters, so nothing a client sends can inject a second
  record or fake a field.
- Bounds: `request_id` 64 characters, `error_message` 512, identity strings 256,
  group lists capped at 32 with `inbound_groups_omitted` /
  `outbound_groups_omitted` reporting the drop.
- Prefer a classified `reason` over raw error text at INFO and WARN. A truncated
  `error_message` appears only on internal failures and at DEBUG.
- `issuer_name` is the configured name. Full issuer URLs are never logged.

## See also

- [Operations: reading the request log](./operations.md#reading-the-request-log)
  — the operator narrative and the fields to grep first.
- [Configuration: logging](./configuration.md#logging) — `--logging-format` and
  `-v`, and the chart values that render them.
- [Caching](./caching.md#observing-the-caches) — `cache.sar.lookup`,
  `cache.tokenreview.lookup` and `authz.sar.completed`.
- [Multi-issuer](./multi-issuer.md#readiness) — `oidc.issuer.*` and
  `issuer_name`.
- [CONTRIBUTING](../CONTRIBUTING.md#logging) — how to add an event.
