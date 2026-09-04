# Logging

<!-- events:begin -->
| `event_type` | components | level | required | summary |
|---|---|---|---|---|
| `audit.backend.failed` | `audit` | ERROR | `error_message` | The audit backend did not start. |
| `audit.backend.started` | `audit` | INFO | `backend_kind` | The audit backend is running. |
| `audit.flush.completed` | `audit` | INFO | `duration_ms` | The pre-shutdown audit flush succeeded. |
| `audit.flush.failed` | `audit` | ERROR | `error_message` | The pre-shutdown audit flush failed. |
| `authn.oidc.failed` | `oidc` | DEBUG | `request_id`, `reason` | The OIDC authenticator rejected the token. The denial itself is INFO on request.access.decided. |
| `authn.oidc.succeeded` | `oidc` | DEBUG | `request_id` | The OIDC authenticator accepted the token. Carries issuer_name when known. |
| `authn.token.missing` | `tokenreview` | DEBUG | `request_id` | No bearer token was presented on the TokenReview path. |
| `authn.tokenreview.completed` | `tokenreview` | DEBUG | `request_id`, `authenticated` | A TokenReview answered. Carries duration_ms on a live call. |
| `authn.tokenreview.failed` | `tokenreview` | ERROR | `request_id`, `reason`, `error_message` | The API server was unreachable or returned a status error. Carries reason=authentication_dependency_error. |
| `authz.impersonation.resolved` | `sar` | DEBUG | `request_id`, `target_kind`, `target_name` | The whole impersonation sequence was allowed. A denial is request.access.decided with decision=deny and reason=impersonation_denied. |
| `authz.sar.completed` | `sar` | DEBUG | `request_id`, `decision`, `duration_ms`, `request_coalesced`, `target_kind` | A live or shared SubjectAccessReview returned. Fires once per impersonation header value, so one request can emit several. |
| `authz.sar.failed` | `sar` | ERROR | `request_id`, `reason`, `error_message` | The SubjectAccessReview call failed. Carries reason=authorization_dependency_error. |
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
| `upstream.request.failed` | `upstream` | ERROR | `request_id`, `reason`, `termination`, `error_message` | The reverse proxy transport failed. Carries reason=upstream_error and a classified termination. |
<!-- events:end -->
