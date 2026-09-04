// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"log/slog"
	"sort"
)

// EventType names the shape of a record. Values are exactly three lowercase
// segments, <domain>.<object>.<action>, and every emitted value is one of the
// constants below. No call site builds an event_type from a string.
type EventType string

const (
	EventRequestAccessDecided        EventType = "request.access.decided"
	EventRequestResponseStarted      EventType = "request.response.started"
	EventRequestResponseCompleted    EventType = "request.response.completed"
	EventRequestHeadersRewritten     EventType = "request.headers.rewritten"
	EventRequestHeadersDropped       EventType = "request.headers.dropped"
	EventRequestAnomalyDetected      EventType = "request.anomaly.detected"
	EventRequestImpersonationApplied EventType = "request.impersonation.applied"
	EventRequestImpersonationSkipped EventType = "request.impersonation.skipped"
	EventRequestHandlerFailed        EventType = "request.handler.failed"
	EventAuthnOIDCSucceeded          EventType = "authn.oidc.succeeded"
	EventAuthnOIDCFailed             EventType = "authn.oidc.failed"
	// gosec G101 fires on the "token" substring in the three names below. They
	// are record identifiers, not credentials.
	EventAuthnTokenMissing          EventType = "authn.token.missing"         //nolint:gosec // event identifier, not a credential
	EventAuthnTokenReviewCompleted  EventType = "authn.tokenreview.completed" //nolint:gosec // event identifier, not a credential
	EventAuthnTokenReviewFailed     EventType = "authn.tokenreview.failed"    //nolint:gosec // event identifier, not a credential
	EventAuthzSARCompleted          EventType = "authz.sar.completed"
	EventAuthzSARFailed             EventType = "authz.sar.failed"
	EventAuthzImpersonationResolved EventType = "authz.impersonation.resolved"
	EventCacheSARLookup             EventType = "cache.sar.lookup"
	EventCacheTokenReviewLookup     EventType = "cache.tokenreview.lookup"
	EventOIDCIssuerConfigured       EventType = "oidc.issuer.configured"
	EventOIDCIssuerInitialized      EventType = "oidc.issuer.initialized"
	EventOIDCIssuerPending          EventType = "oidc.issuer.pending"
	EventReadinessProxyReady        EventType = "readiness.proxy.ready"
	EventReadinessServerFailed      EventType = "readiness.server.failed"
	EventProxyConfigLoaded          EventType = "proxy.config.loaded"
	EventProxyConfigInvalid         EventType = "proxy.config.invalid"
	EventProxyServerStarted         EventType = "proxy.server.started"
	EventProxyServerStopped         EventType = "proxy.server.stopped"
	EventProxyShutdownStarted       EventType = "proxy.shutdown.started"
	EventProxyShutdownCompleted     EventType = "proxy.shutdown.completed"
	EventProxyHookCompleted         EventType = "proxy.hook.completed"
	EventProxyHookFailed            EventType = "proxy.hook.failed"
	EventAuditBackendStarted        EventType = "audit.backend.started"
	EventAuditBackendFailed         EventType = "audit.backend.failed"
	EventAuditFlushCompleted        EventType = "audit.flush.completed"
	EventAuditFlushFailed           EventType = "audit.flush.failed"
	EventUpstreamRequestFailed      EventType = "upstream.request.failed"
	EventUpstreamRequestCanceled    EventType = "upstream.request.canceled"
	EventLogWarningSuppressed       EventType = "log.warning.suppressed"
)

// EventSpec is the registry entry for one event type.
type EventSpec struct {
	Components []Component // nil means any component (log.warning.suppressed)
	Level      slog.Level
	Required   []string // attribute keys that must be present and non-empty
	Message    string   // static msg
	Summary    string   // one line for docs
}

// Registry holds one entry per EventType constant. Required lists the mandatory
// attributes beyond time, level, msg, schema_version, component and event_type;
// conditional attributes are documented in the summary, not required here.
var Registry = map[EventType]EventSpec{
	EventRequestAccessDecided: {
		Components: []Component{ComponentRequest},
		Level:      slog.LevelInfo,
		Required:   []string{"request_id", "event", "src_ip", "path", "http_method", "auth_method", "decision"},
		Message:    "access decision",
		Summary:    "Authentication, authorization and proxy admission decided for a request. Carries event=AuSuccess|AuFail.",
	},
	EventRequestResponseStarted: {
		Components: []Component{ComponentRequest},
		Level:      slog.LevelInfo,
		Required:   []string{"request_id", "http_status", "time_to_headers_ms"},
		Message:    "response started",
		Summary:    "First WriteHeader on a long-running request. Mirrors the audit stage ResponseStarted.",
	},
	EventRequestResponseCompleted: {
		Components: []Component{ComponentRequest},
		Level:      slog.LevelInfo,
		Required:   []string{"request_id", "http_status", "duration_ms", "termination"},
		Message:    "request completed",
		Summary:    "The handler returned. The terminal record for every request, mirroring the audit stage ResponseComplete.",
	},
	EventRequestHeadersRewritten: {
		Components: []Component{ComponentRequest},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id", "src_ip", "forwarded_for_untrusted"},
		Message:    "forwarded headers rewritten",
		Summary:    "X-Forwarded-For collapsed to the resolved client IP on the trusted-proxy path. Diagnostic, not a warning: it is the trusted-proxy contract working as configured and fires on every request behind a trusted ingress.",
	},
	EventRequestHeadersDropped: {
		Components: []Component{ComponentRequest},
		Level:      slog.LevelWarn,
		Required:   []string{"request_id", "src_ip", "dropped_headers"},
		Message:    "forwarded headers dropped",
		Summary:    "X-Forwarded-For or X-Real-Ip removed for an untrusted peer, a fully trusted chain or a malformed hop. Carries forwarded_for_untrusted when the client sent an X-Forwarded-For; a client that sent only X-Real-Ip has no chain to report. Token-bucketed.",
	},
	EventRequestAnomalyDetected: {
		Components: []Component{ComponentRequest},
		Level:      slog.LevelWarn,
		Required:   []string{"request_id", "src_ip", "reason"},
		Message:    "request anomaly detected",
		Summary:    "A rejection that indicates an exploit attempt or gross misconfiguration. Token-bucketed; the access record still carries the outcome.",
	},
	EventRequestImpersonationApplied: {
		Components: []Component{ComponentRequest},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id", "outbound_user", "impersonated_header_names"},
		Message:    "impersonation headers applied",
		Summary:    "Outbound impersonation headers built. Header names only, never values.",
	},
	EventRequestImpersonationSkipped: {
		Components: []Component{ComponentRequest},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id", "skip_reason"},
		Message:    "impersonation skipped",
		Summary:    "Impersonation was disabled by flag, or the request took the TokenReview passthrough path.",
	},
	EventRequestHandlerFailed: {
		Components: []Component{ComponentRequest},
		Level:      slog.LevelError,
		Required:   []string{"request_id", "reason", "error_message"},
		Message:    "request handler failed",
		Summary:    "The proxy hit an internal error while handling a request; the access record carries reason=internal_error.",
	},
	EventAuthnOIDCSucceeded: {
		Components: []Component{ComponentOIDC},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id", "issuer_name"},
		Message:    "oidc authentication succeeded",
		Summary:    "The OIDC authenticator accepted the token. Names the issuer that accepted it.",
	},
	EventAuthnOIDCFailed: {
		Components: []Component{ComponentOIDC},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id", "reason"},
		Message:    "oidc authentication failed",
		Summary:    "The OIDC authenticator rejected the token. The denial itself is INFO on request.access.decided.",
	},
	EventAuthnTokenMissing: {
		Components: []Component{ComponentTokenReview},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id"},
		Message:    "bearer token missing",
		Summary:    "No bearer token was presented on the TokenReview path.",
	},
	EventAuthnTokenReviewCompleted: {
		Components: []Component{ComponentTokenReview},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id", "authenticated"},
		Message:    "tokenreview completed",
		Summary:    "A TokenReview answered. Carries duration_ms on a live call.",
	},
	EventAuthnTokenReviewFailed: {
		Components: []Component{ComponentTokenReview},
		Level:      slog.LevelError,
		Required:   []string{"request_id", "reason", "error_message"},
		Message:    "tokenreview failed",
		Summary:    "The API server was unreachable or returned a status error. Carries reason=authentication_dependency_error.",
	},
	EventAuthzSARCompleted: {
		Components: []Component{ComponentSAR},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id", "decision", "duration_ms", "request_coalesced", "target_kind"},
		Message:    "subject access review completed",
		Summary:    "A live or shared SubjectAccessReview returned. Fires once per impersonation header value, so one request can emit several.",
	},
	EventAuthzSARFailed: {
		Components: []Component{ComponentSAR},
		Level:      slog.LevelError,
		Required:   []string{"request_id", "reason", "error_message"},
		Message:    "subject access review failed",
		Summary:    "The SubjectAccessReview call failed. Carries reason=authorization_dependency_error.",
	},
	EventAuthzImpersonationResolved: {
		Components: []Component{ComponentSAR},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id", "target_kind", "target_name"},
		Message:    "impersonation resolved",
		Summary:    "The whole impersonation sequence was allowed. A denial is request.access.decided with decision=deny and reason=impersonation_denied.",
	},
	EventCacheSARLookup: {
		Components: []Component{ComponentSAR},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id", "cache_result"},
		Message:    "subject access review cache lookup",
		Summary:    "One SubjectAccessReview cache consultation. Carries decision on a hit, never the cache key.",
	},
	EventCacheTokenReviewLookup: {
		Components: []Component{ComponentTokenReview},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id", "cache_result"},
		Message:    "tokenreview cache lookup",
		Summary:    "One TokenReview cache consultation. Carries authenticated on a hit, never the cache key.",
	},
	EventOIDCIssuerConfigured: {
		Components: []Component{ComponentOIDC},
		Level:      slog.LevelInfo,
		Required:   []string{"issuer_name", "issuer_count"},
		Message:    "configured OIDC issuers",
		Summary:    "Once per configured issuer at startup.",
	},
	EventOIDCIssuerInitialized: {
		Components: []Component{ComponentOIDC},
		Level:      slog.LevelInfo,
		Required:   []string{"issuer_name", "issuer_state", "ready_issuers", "total_issuers"},
		Message:    "issuer initialized",
		Summary:    "An issuer's JWKS loaded. Carries issuer_state=initialized.",
	},
	EventOIDCIssuerPending: {
		Components: []Component{ComponentOIDC},
		Level:      slog.LevelWarn,
		Required:   []string{"issuer_name", "issuer_state", "pending_reason", "ready_issuers", "total_issuers"},
		Message:    "issuer pending",
		Summary:    "The pending set or a pending reason changed. Carries issuer_state=pending; not emitted on every scrape.",
	},
	EventReadinessProxyReady: {
		Components: []Component{ComponentReadiness},
		Level:      slog.LevelInfo,
		Required:   []string{"ready_issuers", "total_issuers", "readiness_mode"},
		Message:    "proxy ready",
		Summary:    "Readiness latched to ready.",
	},
	EventReadinessServerFailed: {
		Components: []Component{ComponentReadiness},
		Level:      slog.LevelError,
		Required:   []string{"error_message"},
		Message:    "readiness server failed",
		Summary:    "The readiness HTTP server returned an error.",
	},
	EventProxyConfigLoaded: {
		Components: []Component{ComponentStartup},
		Level:      slog.LevelInfo,
		Required:   []string{"version", "config_hash", "issuer_count", "readiness_mode"},
		Message:    "configuration loaded",
		Summary:    "The effective non-secret configuration is fixed.",
	},
	EventProxyConfigInvalid: {
		Components: []Component{ComponentStartup},
		Level:      slog.LevelError,
		Required:   []string{"reason", "error_message"},
		Message:    "configuration invalid",
		Summary:    "The configuration cannot be used, including a CA bundle that cannot be read.",
	},
	EventProxyServerStarted: {
		Components: []Component{ComponentServer},
		Level:      slog.LevelInfo,
		Required:   []string{"address"},
		Message:    "server started",
		Summary:    "The secure listener is serving.",
	},
	EventProxyServerStopped: {
		Components: []Component{ComponentServer},
		Level:      slog.LevelInfo,
		Required:   []string{"duration_ms"},
		Message:    "server stopped",
		Summary:    "The secure listener stopped.",
	},
	EventProxyShutdownStarted: {
		Components: []Component{ComponentShutdown},
		Level:      slog.LevelInfo,
		Required:   []string{"signal"},
		Message:    "shutdown started",
		Summary:    "A termination signal was received. The forced exit is the same event with forced=true.",
	},
	EventProxyShutdownCompleted: {
		Components: []Component{ComponentShutdown},
		Level:      slog.LevelInfo,
		Required:   []string{"duration_ms"},
		Message:    "shutdown completed",
		Summary:    "Listeners stopped, readiness stopped and pre-shutdown hooks finished.",
	},
	EventProxyHookCompleted: {
		Components: []Component{ComponentShutdown},
		Level:      slog.LevelInfo,
		Required:   []string{"hook", "duration_ms"},
		Message:    "shutdown hook completed",
		Summary:    "One record per pre-shutdown hook that finished.",
	},
	EventProxyHookFailed: {
		Components: []Component{ComponentShutdown},
		Level:      slog.LevelError,
		Required:   []string{"hook", "error_message"},
		Message:    "shutdown hook failed",
		Summary:    "A pre-shutdown hook returned an error.",
	},
	EventAuditBackendStarted: {
		Components: []Component{ComponentAudit},
		Level:      slog.LevelInfo,
		Required:   []string{"backend_kind"},
		Message:    "audit backend started",
		Summary:    "The audit backend is running.",
	},
	EventAuditBackendFailed: {
		Components: []Component{ComponentAudit},
		Level:      slog.LevelError,
		Required:   []string{"error_message"},
		Message:    "audit backend failed",
		Summary:    "The audit backend did not start.",
	},
	EventAuditFlushCompleted: {
		Components: []Component{ComponentAudit},
		Level:      slog.LevelInfo,
		Required:   []string{"duration_ms"},
		Message:    "audit flush completed",
		Summary:    "The pre-shutdown audit flush succeeded.",
	},
	EventAuditFlushFailed: {
		Components: []Component{ComponentAudit},
		Level:      slog.LevelError,
		Required:   []string{"error_message"},
		Message:    "audit flush failed",
		Summary:    "The pre-shutdown audit flush failed.",
	},
	EventUpstreamRequestFailed: {
		Components: []Component{ComponentUpstream},
		Level:      slog.LevelError,
		Required:   []string{"request_id", "reason", "termination", "error_message"},
		Message:    "upstream request failed",
		Summary:    "The reverse proxy transport failed. Carries reason=upstream_error and a classified termination.",
	},
	EventUpstreamRequestCanceled: {
		Components: []Component{ComponentUpstream},
		Level:      slog.LevelDebug,
		Required:   []string{"request_id", "reason"},
		Message:    "upstream request canceled",
		Summary:    "The client went away before the upstream response completed. Carries reason=client_canceled.",
	},
	EventLogWarningSuppressed: {
		Components: nil, // any
		Level:      slog.LevelWarn,
		Required:   []string{"warning_reason", "suppressed_count", "interval_seconds"},
		Message:    "warnings suppressed",
		Summary:    "Token-bucket summary of dropped warning records.",
	},
}

// AllEventTypes returns every registered event type, sorted by string value.
func AllEventTypes() []EventType {
	out := make([]EventType, 0, len(Registry))
	for e := range Registry {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Attr returns the event_type attribute for e, so no call site writes the key.
func (e EventType) Attr() slog.Attr { return slog.String("event_type", string(e)) }

// Spec returns the registry entry for e.
func (e EventType) Spec() (EventSpec, bool) {
	s, ok := Registry[e]
	return s, ok
}
