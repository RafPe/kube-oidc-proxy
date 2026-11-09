// Copyright Jetstack Ltd. See LICENSE for details.

// Package reqctx stores request-scoped values on the http.Request context: the
// values one filter decides and a filter or handler further along reads back.
//
// Getters are named for the value they return (ClientIP, Impersonation,
// Termination); where that name is also the value's type, the type carries a
// Record suffix (ImpersonationRecord, TerminationRecord).
package reqctx

import (
	"net"
	"net/http"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/transport"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/clientip"
)

type key int

const (
	impersonationKey key = iota
	clientIPKey
	// originalForwardedForKey preserves the inbound X-Forwarded-For chain
	// WithResolvedClient rewrote, for forensic logging.
	originalForwardedForKey
	// clientRequestIDKey holds the well-formed id the client supplied, whether
	// or not a trusted peer had it adopted as the authoritative one.
	clientRequestIDKey
	issuerNameKey
	decisionKey
	terminationKey
	authMethodKey
)

// WithResolvedClient returns a copy of the request that carries the client IP
// resolved under the trusted-proxy contract (see package clientip), and whose
// forwarding headers have been reduced to what that contract allows, so audit
// sourceIPs, the access record, the Remote-Client-IP impersonation extra and
// the upstream API server all see the same validated client. It is the one
// place the contract is applied; everything downstream reads the result
// through ClientIP and the headers.
//
// X-Real-Ip is always removed: the proxy never honours it. X-Forwarded-For is
// removed when the resolver would ignore it (untrusted peer, fully trusted
// chain, or malformed hop) and collapsed to the single resolved client IP when
// the peer is a trusted proxy. The raw inbound chain is preserved on the
// context and available via OriginalForwardedFor so forensic logging keeps
// seeing what the client actually sent.
//
// The returned request owns a copy of the header map, so the caller's request
// is left exactly as it arrived.
func WithResolvedClient(req *http.Request, trusted []*net.IPNet) *http.Request {
	xff := req.Header.Get(clientip.HeaderForwardedFor)
	ip := clientip.Resolve(req.RemoteAddr, xff, trusted)

	ctx := request.WithValue(req.Context(), clientIPKey, ip)
	if xff != "" {
		ctx = request.WithValue(ctx, originalForwardedForKey, xff)
	}

	out := req.WithContext(ctx)
	out.Header = req.Header.Clone()
	out.Header.Del(clientip.HeaderRealIP)

	switch {
	case xff == "":
	case ip == clientip.PeerHost(req.RemoteAddr):
		// The resolver fell back to the direct peer: nothing in the
		// forwarded chain is trustworthy.
		out.Header.Del(clientip.HeaderForwardedFor)
	default:
		out.Header.Set(clientip.HeaderForwardedFor, ip)
	}

	return out
}

// ClientIP returns the client IP WithResolvedClient recorded for the request.
// A request that never passed through it reports the direct peer, which is
// what the contract resolves to when no proxy is trusted, so a caller outside
// the filter chain still gets a safe answer.
func ClientIP(req *http.Request) string {
	if ip, ok := req.Context().Value(clientIPKey).(string); ok {
		return ip
	}
	return clientip.PeerHost(req.RemoteAddr)
}

// OriginalForwardedFor returns the raw inbound X-Forwarded-For chain as it was
// before WithResolvedClient rewrote it, or "" when there was none.
func OriginalForwardedFor(req *http.Request) string {
	xff, _ := req.Context().Value(originalForwardedForKey).(string)
	return xff
}

// ForwardMode is how an admitted request is sent to the API server. Its values
// double as request.impersonation.skipped's skip_reason for the two modes that
// skip impersonation.
type ForwardMode string

const (
	// ForwardImpersonating sends the request with the proxy's own credentials
	// and Impersonate-* headers naming the outbound identity.
	ForwardImpersonating ForwardMode = "impersonate"

	// ForwardPassthrough sends the request with the client's own bearer token,
	// which the API server authenticates (--token-passthrough).
	ForwardPassthrough ForwardMode = "passthrough"

	// ForwardDisabled sends the request with no credentials at all: OIDC
	// authentication consumed the token and impersonation is turned off
	// (--disable-impersonation), so the API server sees it as anonymous.
	ForwardDisabled ForwardMode = "disabled"
)

// ImpersonationRecord is how a request is forwarded, as decided once by the
// filter that settled it: the token-review filter for a passthrough request,
// the impersonation filter for every other one.
type ImpersonationRecord struct {
	Mode ForwardMode

	// Outbound is what the impersonating round tripper sends as Impersonate-*
	// headers. It is set exactly when Mode is ForwardImpersonating.
	Outbound *transport.ImpersonationConfig

	// InboundUser is the identity the proxy authenticated, or nil on the
	// passthrough path, where the API server authenticates the token itself.
	InboundUser user.Info

	// ImpersonatedUser is the identity the client asked to act as and was
	// allowed to, or nil when the request impersonates nobody and the inbound
	// identity is forwarded as itself.
	ImpersonatedUser user.Info
}

// WithRequestID returns a copy of the request carrying id as the request's
// authoritative correlation id. The id lives under the logging package's key,
// the one Emit reads to supply request_id to any event that requires it, so
// the access record and every other record carry the same id.
func WithRequestID(req *http.Request, id string) *http.Request {
	return req.WithContext(logging.WithRequestID(req.Context(), id))
}

// RequestID returns the request's authoritative correlation id, or "" when the
// request-id filter has not run.
func RequestID(req *http.Request) string {
	return logging.RequestID(req.Context())
}

// WithClientRequestID returns a copy of the request carrying the request id the
// client supplied. It is recorded for correlation only and is never the
// authoritative id unless the peer is a trusted proxy.
func WithClientRequestID(req *http.Request, id string) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), clientRequestIDKey, id))
}

// ClientRequestID returns the client-supplied request id, or "".
func ClientRequestID(req *http.Request) string {
	id, _ := req.Context().Value(clientRequestIDKey).(string)
	return id
}

// WithIssuerName returns a copy of the request carrying the name of the OIDC
// issuer that authenticated it: the host of its URL.
func WithIssuerName(req *http.Request, name string) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), issuerNameKey, name))
}

// IssuerName returns the name WithIssuerName recorded, or "".
func IssuerName(req *http.Request) string {
	name, _ := req.Context().Value(issuerNameKey).(string)
	return name
}

// decisionHolder records that the request's access decision has been written.
// Like the termination holder it is shared by pointer, because the handler that
// writes the decision and the handler that would write a second one see
// different derived requests.
type decisionHolder struct {
	recorded bool
}

// WithDecisionHolder returns a copy of the request carrying the holder that
// keeps the access decision to one record per request.
func WithDecisionHolder(req *http.Request) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), decisionKey, new(decisionHolder)))
}

// MarkDecisionRecorded records that the request's access decision has been
// written. It is a no-op when the request carries no holder, which is the case
// only for a request that never passed through the lifecycle filter.
func MarkDecisionRecorded(req *http.Request) {
	if h, ok := req.Context().Value(decisionKey).(*decisionHolder); ok {
		h.recorded = true
	}
}

// DecisionRecorded reports whether the request's access decision has already
// been written. A request with no holder reports false, so a caller that cannot
// see the holder still records its decision rather than dropping it.
func DecisionRecorded(req *http.Request) bool {
	h, ok := req.Context().Value(decisionKey).(*decisionHolder)
	return ok && h.recorded
}

// TerminationRecord is how a request ended, as classified by a handler deeper
// in the chain than the lifecycle filter that reports it. Reason is the closed
// access-record reason that goes with it, or metrics.ReasonNone.
type TerminationRecord struct {
	Kind   metrics.Termination
	Reason metrics.Reason
}

// WithTerminationHolder returns a copy of the request carrying an empty
// termination the lifecycle filter reads once the handler has returned.
//
// The holder is a pointer on purpose. The handler that classifies the failure
// sees a request derived several filters further down, and a context value
// written there is invisible to the filter that installed it; a write through
// the shared holder is not.
func WithTerminationHolder(req *http.Request) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), terminationKey, new(TerminationRecord)))
}

// MarkTermination writes how the request ended onto the holder the lifecycle
// filter installed. It is a no-op when the request carries no holder, so a
// handler called outside that filter needs no special case.
func MarkTermination(req *http.Request, kind metrics.Termination, reason metrics.Reason) {
	if h, ok := req.Context().Value(terminationKey).(*TerminationRecord); ok {
		h.Kind = kind
		h.Reason = reason
	}
}

// Termination returns the termination a handler classified for the request,
// or the zero value when none did.
func Termination(req *http.Request) TerminationRecord {
	h, ok := req.Context().Value(terminationKey).(*TerminationRecord)
	if !ok {
		return TerminationRecord{}
	}

	return *h
}

// WithAuthMethod returns a copy of the request recording how it authenticated.
// It is set by the handler that accepted the credential and read by the access
// record, which runs after the decision on both the success and failure paths.
func WithAuthMethod(req *http.Request, method metrics.AuthMethod) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), authMethodKey, method))
}

// AuthMethod returns how the request authenticated. A request refused before
// any authenticator accepted its credential reports metrics.AuthMethodNone.
func AuthMethod(req *http.Request) metrics.AuthMethod {
	if method, ok := req.Context().Value(authMethodKey).(metrics.AuthMethod); ok && method != "" {
		return method
	}
	return metrics.AuthMethodNone
}

// WithImpersonation returns a copy of the request carrying how it is to be
// forwarded. When the request impersonates someone, that identity also becomes
// the request's user so the audit chain records who was acted as.
func WithImpersonation(req *http.Request, imp *ImpersonationRecord) *http.Request {
	ctx := request.WithValue(req.Context(), impersonationKey, imp)
	if imp.ImpersonatedUser != nil {
		ctx = request.WithUser(ctx, imp.ImpersonatedUser)
	}
	return req.WithContext(ctx)
}

// Impersonation returns how the request is to be forwarded, or nil while no
// filter has decided it yet.
func Impersonation(req *http.Request) *ImpersonationRecord {
	imp, _ := req.Context().Value(impersonationKey).(*ImpersonationRecord)
	return imp
}
