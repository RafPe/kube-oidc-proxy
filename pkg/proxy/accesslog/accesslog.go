// Copyright Jetstack Ltd. See LICENSE for details.

// Package accesslog emits the proxy's access record: one
// request.access.decided per request, carrying the authentication,
// authorization and admission outcome.
//
// The record's src_ip is the client IP the reqctx package resolved
// under the trusted-proxy contract (see that package's documentation); this
// package does not resolve addresses itself, so the access record, the audit
// log and the Remote-Client-IP impersonation extra can never disagree. The raw
// forwarded chain is still emitted for observability under the
// explicitly-untrusted "forwarded_for_untrusted" field and must not be treated
// as identity.
package accesslog

import (
	"log/slog"
	"net/http"

	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
)

// The two values of the record's event field, the one the request.access.decided
// registry entry documents. Decision.Allowed picks between them.
const (
	eventSuccess = "AuSuccess"
	eventFail    = "AuFail"
)

// loggableExtraKeys is the allowlist of impersonation-extra keys that the proxy
// sets itself and are safe to log. Everything else is authenticator-supplied
// claim data and is counted, not logged, so arbitrary claims and credentials
// never reach the log stream. reqctx.ExtraKeyOriginalExtra is deliberately absent: it
// carries the original identity's whole extra map, which is claim data.
var loggableExtraKeys = map[string]struct{}{
	reqctx.UserHeaderClientIPKey:  {},
	reqctx.ExtraKeyOriginalUser:   {},
	reqctx.ExtraKeyOriginalGroups: {},
	reqctx.ExtraKeyOriginalUID:    {},
}

// Logger writes the access record. It is an injected collaborator rather than
// a package global so that the destination and the component are decided once
// at construction and a test can hold its own.
type Logger struct {
	logger *slog.Logger
}

// New returns a Logger emitting through logger, which the caller has already
// bound to the request component. logger is required.
func New(logger *slog.Logger) *Logger {
	return &Logger{logger: logger}
}

// Decision is the outcome the access record reports. Reason, TargetKind and
// TargetName describe a denial and are ignored when Allowed is true: an allow
// has nothing to explain, and a reason on it would break the closed value set
// the field is queried by.
type Decision struct {
	// Allowed selects AuSuccess/allow over AuFail/deny.
	Allowed bool

	// Reason is one of the closed reason values, on a denial only.
	Reason metrics.Reason

	// AuthMethod is how the request authenticated.
	AuthMethod metrics.AuthMethod

	// Inbound is the authenticated identity that made the request;
	// Impersonated is the identity the client impersonated, when it asked to
	// act as someone else and was allowed to. Either may be nil. The record
	// reports Impersonated under the outbound_* fields, which is what the API
	// server is asked to act as.
	Inbound      user.Info
	Impersonated user.Info

	// TargetKind and TargetName name the impersonation target that was refused,
	// so a denial does not have to be recovered by parsing the error text.
	TargetKind subjectaccessreview.TargetKind
	TargetName string
}

// LogDecision emits the request.access.decided record for a request. It is
// called as soon as authentication, authorization and proxy admission are
// decided, so a watch or exec that runs for hours is recorded immediately.
// Keeping it to one record per request is the caller's job: this writes
// whatever it is handed.
func (a *Logger) LogDecision(req *http.Request, d Decision) {
	event := eventFail
	if d.Allowed {
		event = eventSuccess
	}

	attrs := []slog.Attr{
		slog.String("request_id", logging.Bound(reqctx.RequestID(req), logging.MaxRequestID)),
	}
	if id := reqctx.ClientRequestID(req); id != "" {
		attrs = append(attrs, slog.String("client_request_id", logging.Bound(id, logging.MaxRequestID)))
	}

	attrs = append(attrs,
		slog.String("event", event),
		slog.String("src_ip", reqctx.ClientIP(req)),
		slog.String("path", logging.Sanitize(req.URL.Path)),
	)
	if fwd := untrustedForwardedFor(req); fwd != "" {
		attrs = append(attrs, slog.String("forwarded_for_untrusted", fwd))
	}

	attrs = append(attrs,
		slog.String("http_method", req.Method),
		slog.String("auth_method", string(d.AuthMethod)),
	)
	if name := reqctx.IssuerName(req); name != "" {
		attrs = append(attrs, slog.String("issuer_name", logging.Bound(name, logging.MaxIdentity)))
	}

	attrs = append(attrs, kubernetesAttrs(req)...)
	attrs = append(attrs, slog.String("decision", string(metrics.DecisionFor(d.Allowed))))

	if !d.Allowed {
		if d.Reason != "" {
			attrs = append(attrs, slog.String("reason", string(d.Reason)))
		}
		if d.TargetKind != "" {
			attrs = append(attrs, slog.String("target_kind", string(d.TargetKind)))
		}
		if d.TargetName != "" {
			attrs = append(attrs, slog.String("target_name", logging.Bound(d.TargetName, logging.MaxIdentity)))
		}
	}

	if d.Inbound != nil {
		attrs = append(attrs, userAttrs("inbound", d.Inbound)...)
	}
	if d.Impersonated != nil {
		attrs = append(attrs, userAttrs("outbound", d.Impersonated)...)
	}

	logging.Emit(req.Context(), a.logger, logging.EventRequestAccessDecided, attrs...)
}

// untrustedForwardedFor returns the raw forwarded chain the client actually
// sent, sanitized. It is forensic: WithResolvedClient preserved the inbound
// value on the context before rewriting the header, so the record reports what
// arrived rather than what was forwarded. A request that never passed through
// it still has the header itself.
func untrustedForwardedFor(req *http.Request) string {
	raw := reqctx.OriginalForwardedFor(req)
	if raw == "" {
		raw = req.Header.Get(reqctx.HeaderForwardedFor)
	}
	return logging.Sanitize(raw)
}

// kubernetesAttrs renders the API dimensions the request-info resolver
// determined. A non-resource path (healthz, discovery, the metrics endpoint)
// carries none, so a query on k8s_resource only ever matches API traffic.
func kubernetesAttrs(req *http.Request) []slog.Attr {
	info, ok := genericapirequest.RequestInfoFrom(req.Context())
	if !ok || info == nil || !info.IsResourceRequest {
		return nil
	}

	// k8s_api_group is present with an empty value for the core group, which is
	// how the API itself names it.
	attrs := []slog.Attr{
		slog.String("k8s_verb", logging.Sanitize(info.Verb)),
		slog.String("k8s_api_group", logging.Sanitize(info.APIGroup)),
		slog.String("k8s_resource", logging.Sanitize(info.Resource)),
	}
	if info.Subresource != "" {
		attrs = append(attrs, slog.String("k8s_subresource", logging.Sanitize(info.Subresource)))
	}
	if info.Namespace != "" {
		attrs = append(attrs, slog.String("k8s_namespace", logging.Sanitize(info.Namespace)))
	}
	if info.Name != "" {
		attrs = append(attrs, slog.String("k8s_name", logging.Bound(info.Name, logging.MaxIdentity)))
	}
	return attrs
}

// userAttrs renders a user.Info as sanitized, structured fields under the given
// prefix. Groups are capped and the drop is reported rather than hidden; only
// allowlisted extras are logged, and the number of omitted claim keys is
// reported so operators can tell data was dropped.
func userAttrs(prefix string, u user.Info) []slog.Attr {
	groups, groupsOmitted := logging.BoundedList(u.GetGroups(), logging.MaxGroups)

	attrs := []slog.Attr{
		slog.String(prefix+"_user", logging.Bound(u.GetName(), logging.MaxIdentity)),
		slog.Any(prefix+"_groups", groups),
	}
	if groupsOmitted > 0 {
		attrs = append(attrs, slog.Int(prefix+"_groups_omitted", groupsOmitted))
	}
	if uid := u.GetUID(); uid != "" {
		attrs = append(attrs, slog.String(prefix+"_uid", logging.Bound(uid, logging.MaxIdentity)))
	}
	safe, omitted := loggableExtras(u.GetExtra())
	if len(safe) > 0 {
		attrs = append(attrs, slog.Any(prefix+"_extra", safe))
	}
	if omitted > 0 {
		attrs = append(attrs, slog.Int(prefix+"_extra_omitted", omitted))
	}
	return attrs
}

// loggableExtras splits an extra map into the allowlisted, sanitized entries
// safe to log and a count of the omitted (non-allowlisted) keys. The kept
// values carry no cap: they are part of the frozen record shape and the group
// cap does not apply to them.
func loggableExtras(extra map[string][]string) (map[string][]string, int) {
	if len(extra) == 0 {
		return nil, 0
	}
	safe := make(map[string][]string)
	omitted := 0
	for k, v := range extra {
		if _, ok := loggableExtraKeys[k]; ok {
			safe[logging.Sanitize(k)] = logging.SanitizeList(v)
			continue
		}
		omitted++
	}
	return safe, omitted
}
