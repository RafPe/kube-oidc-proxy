// Copyright Jetstack Ltd. See LICENSE for details.

// Package accesslog emits the proxy's access record: one
// request.access.decided per request, carrying the authentication,
// authorization and admission outcome.
//
// The record's src_ip is the client IP resolved under the trusted-proxy
// contract (see package clientip) and carried on the request by reqctx; this
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

	"github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/clientip"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
)

// The two values of the record's event field, the one the request.access.decided
// registry entry documents. Decision.Allowed picks between them.
const (
	eventSuccess = "AuSuccess"
	eventFail    = "AuFail"
)

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

// LogDecision emits the request.access.decided record for a request through
// logger, which the caller has bound to the request component. It is called
// as soon as authentication, authorization and proxy admission are decided,
// so a watch or exec that runs for hours is recorded immediately. Keeping it
// to one record per request is the caller's job: this writes whatever it is
// handed.
func LogDecision(logger *slog.Logger, req *http.Request, d Decision) {
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

	logging.Emit(req.Context(), logger, logging.EventRequestAccessDecided, attrs...)
}

// untrustedForwardedFor returns the raw forwarded chain the client actually
// sent, sanitized. It is forensic: WithResolvedClient preserved the inbound
// value on the context before rewriting the header, so the record reports what
// arrived rather than what was forwarded. A request that never passed through
// it still has the header itself.
func untrustedForwardedFor(req *http.Request) string {
	raw := reqctx.OriginalForwardedFor(req)
	if raw == "" {
		raw = req.Header.Get(clientip.HeaderForwardedFor)
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
// prefix. Groups are capped and the drop is reported rather than hidden.
//
// Extras are never logged, only counted. An identity's extras are whatever its
// authenticator put there, which is claim data: arbitrary, and possibly
// credentials. The extras the proxy adds on the forwarded request are not part
// of either identity, and the record already carries what they say: src_ip is
// Remote-Client-IP, and the inbound_* fields are the originaluser.jetstack.io-*
// extras.
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
	if omitted := len(u.GetExtra()); omitted > 0 {
		attrs = append(attrs, slog.Int(prefix+"_extra_omitted", omitted))
	}
	return attrs
}
