// Copyright Jetstack Ltd. See LICENSE for details.

// Package reqctx stores request-scoped values on the http.Request context and
// owns the proxy's client-IP resolution.
//
// # Client-IP and trusted-proxy semantics (see issue #56)
//
// The immediate peer (req.RemoteAddr) is always authoritative for the client
// IP. X-Forwarded-For is honoured ONLY to the extent that the hops closest to
// the proxy are themselves within a configured trusted-proxy network: the chain
// is walked right-to-left, trusted hops are skipped, and the first untrusted
// address is taken as the client. When no trusted proxies are configured (the
// default), forwarded headers are never trusted and the direct peer is used, so
// an untrusted client cannot spoof its resolved IP.
//
// WithResolvedClient applies this contract once per request: it records the
// resolved client IP on the context, where ClientIP reads it back, and reduces
// the forwarding headers to what the contract allows, so audit sourceIPs, the
// access record, the Remote-Client-IP impersonation extra and the upstream API
// server all see the same validated client. The trusted networks are passed in
// by the caller that owns them; this package holds no process-wide state.
//
// Only X-Forwarded-For is parsed; the RFC 7239 Forwarded header is not honoured.
// On a malformed forwarded hop, or when the entire chain is itself trusted, the
// direct peer is returned.
package reqctx

import (
	"net"
	"net/http"
	"strings"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/transport"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

type key int

const (
	// noImpersonationKey is the context key for whether to use impersonation.
	noImpersonationKey key = iota

	// impersonationConfigKey is the context key for the impersonation config.
	impersonationConfigKey

	// clientIPKey is the context key for the resolved client IP.
	clientIPKey

	// originalForwardedForKey is the context key preserving the raw inbound
	// X-Forwarded-For chain before sanitization, for forensic logging.
	originalForwardedForKey

	// clientRequestIDKey is the context key for a well-formed request id the
	// client supplied that was NOT adopted as the authoritative id.
	clientRequestIDKey

	// issuerNameKey is the context key for the configured name of the OIDC
	// issuer that authenticated the request.
	issuerNameKey

	// decisionKey is the context key for the holder that records whether the
	// request's single access decision has already been written.
	decisionKey

	// terminationKey is the context key for the holder the request lifecycle
	// filter installs so a handler further down the chain can classify how the
	// request ended.
	terminationKey

	// authMethodKey is the context key for how the request authenticated.
	authMethodKey
)

// The inbound forwarding headers the trusted-proxy contract owns. They are
// exported so every reader of the headers spells them the same way.
const (
	HeaderForwardedFor = "X-Forwarded-For"
	HeaderRealIP       = "X-Real-Ip"
)

// WithResolvedClient returns a copy of the request that carries the client IP
// resolved under the trusted-proxy contract, and whose forwarding headers have
// been reduced to what that contract allows. It is the one place the contract
// is applied; everything downstream reads the result through ClientIP and the
// headers.
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
	xff := req.Header.Get(HeaderForwardedFor)
	clientIP := ResolveClientIP(req.RemoteAddr, xff, trusted)

	ctx := request.WithValue(req.Context(), clientIPKey, clientIP)
	if xff != "" {
		ctx = request.WithValue(ctx, originalForwardedForKey, xff)
	}

	out := req.WithContext(ctx)
	out.Header = req.Header.Clone()
	out.Header.Del(HeaderRealIP)

	switch {
	case xff == "":
	case clientIP == PeerHost(req.RemoteAddr):
		// The resolver fell back to the direct peer: nothing in the
		// forwarded chain is trustworthy.
		out.Header.Del(HeaderForwardedFor)
	default:
		out.Header.Set(HeaderForwardedFor, clientIP)
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
	return PeerHost(req.RemoteAddr)
}

// OriginalForwardedFor returns the raw inbound X-Forwarded-For chain as it was
// before WithResolvedClient rewrote it, or "" when there was none.
func OriginalForwardedFor(req *http.Request) string {
	xff, _ := req.Context().Value(originalForwardedForKey).(string)
	return xff
}

// ImpersonationRequest is the outbound identity the impersonation filter
// resolved for a request, together with the inbound identity it was derived
// from. ImpersonatedUser is nil when the request impersonates nobody and the
// inbound identity is forwarded as itself.
type ImpersonationRequest struct {
	ImpersonationConfig *transport.ImpersonationConfig
	InboundUser         user.Info
	ImpersonatedUser    user.Info
}

// WithNoImpersonation returns a copy of the request in which the noImpersonation context value is set.
func WithNoImpersonation(req *http.Request) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), noImpersonationKey, true))
}

// NoImpersonation returns whether the noImpersonation context key has been set
func NoImpersonation(req *http.Request) bool {
	noImp, _ := req.Context().Value(noImpersonationKey).(bool)
	return noImp
}

// WithRequestID returns a copy of the request carrying id as the request's
// authoritative correlation id. The id lives under the logging package's key,
// the one Emit reads to supply request_id to any event that requires it, so
// the access record and every other record agree on it by construction.
func WithRequestID(req *http.Request, id string) *http.Request {
	return req.WithContext(logging.WithRequestID(req.Context(), id))
}

// RequestID returns the request's authoritative correlation id, or "" when the
// request-id filter has not run.
func RequestID(req *http.Request) string {
	return logging.RequestIDFrom(req.Context())
}

// WithClientRequestID returns a copy of the request carrying the request id the
// client supplied. It is recorded for correlation only and is never the
// authoritative id unless the peer is a trusted proxy.
func WithClientRequestID(req *http.Request, id string) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), clientRequestIDKey, id))
}

// ClientRequestID returns the client-supplied request id, or "" when the client
// sent none that was well-formed.
func ClientRequestID(req *http.Request) string {
	id, _ := req.Context().Value(clientRequestIDKey).(string)
	return id
}

// WithIssuerName returns a copy of the request carrying the configured name of
// the OIDC issuer that authenticated it.
func WithIssuerName(req *http.Request, name string) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), issuerNameKey, name))
}

// IssuerName returns the configured name of the OIDC issuer that authenticated
// the request, or "" when it is not known.
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
// written. It is a no-op when the request carries no holder, so a decision
// logged outside the request chain needs no special case.
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

// Termination is how a request ended, as classified by a handler deeper in the
// chain than the lifecycle filter that reports it. Reason is the closed
// access-record reason that goes with it, or metrics.ReasonNone.
type Termination struct {
	Termination metrics.Termination
	Reason      metrics.Reason
}

// WithTerminationHolder returns a copy of the request carrying an empty
// termination the lifecycle filter reads once the handler has returned.
//
// The holder is a pointer on purpose. The handler that classifies the failure
// sees a request derived several filters further down, and a context value
// written there is invisible to the filter that installed it; a write through
// the shared holder is not.
func WithTerminationHolder(req *http.Request) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), terminationKey, new(Termination)))
}

// RecordTermination writes how the request ended onto the holder the lifecycle
// filter installed. Like MarkDecisionRecorded it mutates shared state rather
// than deriving a request, and it is a no-op when the request carries no
// holder, so a handler called outside that filter -- a test, or an error on a
// request that never reached it -- needs no special case.
func RecordTermination(req *http.Request, termination metrics.Termination, reason metrics.Reason) {
	if h, ok := req.Context().Value(terminationKey).(*Termination); ok {
		h.Termination = termination
		h.Reason = reason
	}
}

// TerminationFrom returns the termination a handler classified for the
// request, or the zero value when none did.
func TerminationFrom(req *http.Request) Termination {
	h, ok := req.Context().Value(terminationKey).(*Termination)
	if !ok {
		return Termination{}
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

// WithImpersonationConfig returns a copy of the request carrying the resolved
// outbound identity. When the request impersonates someone, that identity also
// becomes the request's user so the audit chain records who was acted as.
func WithImpersonationConfig(req *http.Request, conf *ImpersonationRequest) *http.Request {
	ctxToReturn := request.WithValue(req.Context(), impersonationConfigKey, conf)
	if conf.ImpersonatedUser != nil {
		ctxToReturn = request.WithUser(ctxToReturn, conf.ImpersonatedUser)
	}
	return req.WithContext(ctxToReturn)
}

// ImpersonationConfig returns the impersonation configuration held in the context if existing.
func ImpersonationConfig(req *http.Request) *ImpersonationRequest {
	conf, _ := req.Context().Value(impersonationConfigKey).(*ImpersonationRequest)
	return conf
}

// ResolveClientIP returns the authoritative client IP for a request given the
// peer address, the X-Forwarded-For chain, and the set of trusted proxy
// networks. See the package documentation for the full contract. It is
// IPv4/IPv6 aware and ignores malformed forwarded entries.
func ResolveClientIP(remoteAddr, xff string, trusted []*net.IPNet) string {
	peer := PeerHost(remoteAddr)

	// Without trust, or when the peer itself is not a trusted proxy, forwarded
	// headers are ignored entirely: the direct peer is the client.
	if xff == "" || !IPInNetworks(peer, trusted) {
		return peer
	}

	// The peer is a trusted proxy. Walk the forwarded chain from the hop nearest
	// the proxy toward the origin, skipping trusted hops, and take the first
	// untrusted address as the client.
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(hops[i])
		if net.ParseIP(ip) == nil {
			// Malformed hop: cannot trust anything further left through it.
			return peer
		}
		if IPInNetworks(ip, trusted) {
			continue
		}
		return ip
	}

	return peer
}

// PeerHost extracts the host portion of a host:port peer address, IPv6-safe. It
// falls back to the raw value when the address has no port (some call sites
// build requests without a RemoteAddr).
func PeerHost(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// IPInNetworks reports whether ip parses and falls within any of the networks.
func IPInNetworks(ip string, networks []*net.IPNet) bool {
	if len(networks) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range networks {
		if n != nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}
