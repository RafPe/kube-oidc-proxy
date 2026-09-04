// Copyright Jetstack Ltd. See LICENSE for details.

// Package logging emits the proxy's access record: one
// request.access.decided per request, carrying the authentication,
// authorization and admission outcome.
//
// # Client-IP and trusted-proxy semantics (see issue #56)
//
// The immediate peer (req.RemoteAddr) is always authoritative for the client
// IP. X-Forwarded-For is honoured ONLY to the extent that the hops closest to
// the proxy are themselves within a configured trusted-proxy network: the chain
// is walked right-to-left, trusted hops are skipped, and the first untrusted
// address is taken as the client. When no trusted proxies are configured (the
// default), forwarded headers are never trusted and the direct peer is used, so
// an untrusted client cannot spoof its resolved IP. The networks are held by
// the AccessLogger, not by a package global, so a test can build one without
// disturbing the process. The raw forwarded chain is still emitted for
// observability under the explicitly-untrusted "forwarded_for_untrusted" field
// and must not be treated as identity.
package logging

import (
	"log/slog"
	"net"
	"net/http"
	"strings"

	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	proxycontext "github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
)

const (
	UserHeaderClientIPKey = "Remote-Client-IP"
)

// loggableExtraKeys is the allowlist of impersonation-extra keys that the proxy
// sets itself and are safe to log. Everything else is authenticator-supplied
// claim data and is counted, not logged, so arbitrary claims and credentials
// never reach the log stream.
var loggableExtraKeys = map[string]struct{}{
	UserHeaderClientIPKey:             {},
	"originaluser.jetstack.io-user":   {},
	"originaluser.jetstack.io-groups": {},
	"originaluser.jetstack.io-uid":    {},
}

// AccessLogger writes the access record. It is an injected collaborator rather
// than a package global so that the destination, the component and the trusted
// proxies are decided once at construction and a test can hold its own.
type AccessLogger struct {
	logger *slog.Logger

	// trustedProxies holds the networks whose forwarded headers are honoured
	// when resolving the client IP. Empty (the default) trusts no proxy.
	trustedProxies []*net.IPNet
}

// NewAccessLogger returns an AccessLogger emitting through logger, which the
// caller has already bound to the request component. A nil logger yields one
// that discards every record, so a partially wired caller cannot panic the
// request path.
func NewAccessLogger(logger *slog.Logger, trustedProxies []*net.IPNet) *AccessLogger {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &AccessLogger{logger: logger, trustedProxies: trustedProxies}
}

// Decision is the outcome the access record reports. Reason, TargetKind and
// TargetName describe a denial and are ignored when Allowed is true: an allow
// has nothing to explain, and a reason on it would break the closed value set
// the field is queried by.
type Decision struct {
	// Allowed selects AuSuccess/allow over AuFail/deny.
	Allowed bool

	// Reason is one of the closed reason values, on a denial only.
	Reason string

	// AuthMethod is oidc, tokenreview or none.
	AuthMethod string

	// Inbound is the authenticated identity that made the request; Outbound is
	// the identity forwarded upstream when impersonation resolved a different
	// one. Either may be nil.
	Inbound  user.Info
	Outbound user.Info

	// TargetKind and TargetName name the impersonation target that was refused,
	// so a denial does not have to be recovered by parsing the error text.
	TargetKind string
	TargetName string
}

// LogDecision emits the single request.access.decided record for a request. It
// is called as soon as authentication, authorization and proxy admission are
// decided, so a watch or exec that runs for hours is recorded immediately.
func (a *AccessLogger) LogDecision(req *http.Request, d Decision) {
	event, decision := "AuFail", "deny"
	if d.Allowed {
		event, decision = "AuSuccess", "allow"
	}

	attrs := []slog.Attr{
		slog.String("request_id", logging.Bound(proxycontext.RequestID(req), logging.MaxRequestID)),
	}
	if id := proxycontext.ClientRequestID(req); id != "" {
		attrs = append(attrs, slog.String("client_request_id", logging.Bound(id, logging.MaxRequestID)))
	}

	attrs = append(attrs,
		slog.String("event", event),
		slog.String("src_ip", resolveClientIP(req.RemoteAddr, forwardedFor(req.Header), a.trustedProxies)),
		slog.String("path", sanitizePath(req)),
	)
	if fwd := untrustedForwardedFor(req); fwd != "" {
		attrs = append(attrs, slog.String("forwarded_for_untrusted", fwd))
	}

	attrs = append(attrs,
		slog.String("http_method", req.Method),
		slog.String("auth_method", d.AuthMethod),
	)
	if name := proxycontext.IssuerName(req); name != "" {
		attrs = append(attrs, slog.String("issuer_name", logging.Bound(name, logging.MaxIdentity)))
	}

	attrs = append(attrs, kubernetesAttrs(req)...)
	attrs = append(attrs, slog.String("decision", decision))

	if !d.Allowed {
		if d.Reason != "" {
			attrs = append(attrs, slog.String("reason", d.Reason))
		}
		if d.TargetKind != "" {
			attrs = append(attrs, slog.String("target_kind", d.TargetKind))
		}
		if d.TargetName != "" {
			attrs = append(attrs, slog.String("target_name", logging.Bound(d.TargetName, logging.MaxIdentity)))
		}
	}

	if d.Inbound != nil {
		attrs = append(attrs, userAttrs("inbound", d.Inbound)...)
	}
	if d.Outbound != nil {
		attrs = append(attrs, userAttrs("outbound", d.Outbound)...)
	}

	logging.Emit(req.Context(), a.logger, logging.EventRequestAccessDecided, attrs...)
}

// untrustedForwardedFor returns the raw forwarded chain the client actually
// sent, sanitized. It is forensic: SanitizeForwardHeaders preserved the inbound
// value on the context before rewriting the header, so the record reports what
// arrived rather than what was forwarded.
func untrustedForwardedFor(req *http.Request) string {
	raw := proxycontext.OriginalForwardedFor(req)
	if raw == "" {
		raw = forwardedFor(req.Header)
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

// sanitizePath returns the request path with query string and control
// characters stripped, guarding against a nil URL (requests are constructed
// without one in some call sites).
func sanitizePath(req *http.Request) string {
	if req.URL == nil {
		return ""
	}
	return logging.Sanitize(req.URL.Path)
}

// forwardedFor returns the raw X-Forwarded-For header value.
func forwardedFor(headers http.Header) string {
	return headers.Get("X-Forwarded-For")
}

// resolveClientIP returns the authoritative client IP for a request given the
// peer address, the X-Forwarded-For chain, and the set of trusted proxy
// networks. See the package documentation for the full contract. It is
// IPv4/IPv6 aware and ignores malformed forwarded entries.
func resolveClientIP(remoteAddr, xff string, trusted []*net.IPNet) string {
	peer := proxycontext.PeerHost(remoteAddr)

	// Without trust, or when the peer itself is not a trusted proxy, forwarded
	// headers are ignored entirely: the direct peer is the client.
	if xff == "" || !proxycontext.IPInNetworks(peer, trusted) {
		return peer
	}

	// The peer is a trusted proxy. Walk the forwarded chain from the hop
	// nearest the proxy toward the origin, skipping trusted hops, and take the
	// first untrusted (or malformed-but-parseable) address as the client.
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(hops[i])
		if net.ParseIP(ip) == nil {
			// Malformed hop: cannot trust anything further left through it.
			return peer
		}
		if proxycontext.IPInNetworks(ip, trusted) {
			continue
		}
		return ip
	}

	return peer
}
