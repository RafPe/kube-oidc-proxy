// Copyright Jetstack Ltd. See LICENSE for details.

// Package context stores request-scoped values on the http.Request context and
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
// an untrusted client cannot spoof its resolved IP. Configure trusted networks
// with SetTrustedProxies. SanitizeForwardHeaders applies this contract to the
// headers themselves, so audit sourceIPs and the upstream API server see only
// validated forwarding information.
//
// Only X-Forwarded-For is parsed; the RFC 7239 Forwarded header is not honoured.
// On a malformed forwarded hop, or when the entire chain is itself trusted, the
// direct peer is returned. This contract is intentionally identical to the
// resolver in the logging package so that the audit-log client IP and the
// Remote-Client-IP impersonation extra never disagree.
package context

import (
	"net"
	"net/http"
	"strings"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/transport"
)

type key int

const (
	// noImpersonationKey is the context key for whether to use impersonation.
	noImpersonationKey key = iota

	// impersonationConfigKey is the context key for the impersonation config.
	impersonationConfigKey

	// bearerTokenKey is the context key for the bearer token.
	bearerTokenKey

	// bearerTokenKey is the context key for the client address.
	clientAddressKey

	// originalForwardedForKey is the context key preserving the raw inbound
	// X-Forwarded-For chain before sanitization, for forensic logging.
	originalForwardedForKey

	// requestIDKey is the context key for the request's authoritative
	// correlation id, minted or adopted by the request-id filter.
	requestIDKey

	// clientRequestIDKey is the context key for a well-formed request id the
	// client supplied that was NOT adopted as the authoritative id.
	clientRequestIDKey

	// issuerNameKey is the context key for the configured name of the OIDC
	// issuer that authenticated the request.
	issuerNameKey
)

// trustedProxies holds the networks whose forwarded headers are honoured when
// resolving the client IP. Empty (the default) means no proxy is trusted, so
// the direct peer is always used.
var trustedProxies []*net.IPNet

// SetTrustedProxies configures the trusted-proxy networks used when resolving
// the client IP from forwarded headers. Passing nil (the default) disables
// forwarded-header trust entirely. Intended to be called once at startup before
// requests are served.
func SetTrustedProxies(nets []*net.IPNet) {
	trustedProxies = nets
}

// SanitizeForwardHeaders enforces the trusted-proxy contract on the inbound
// forwarding headers before anything downstream reads them: the audit filters
// (which fill the event's sourceIPs from these headers via utilnet.SourceIPs),
// the access log, and the upstream API server the request is forwarded to.
//
// X-Real-Ip is always removed — the proxy never honours it. X-Forwarded-For is
// removed when the resolver would ignore it (untrusted peer, fully trusted
// chain, or malformed hop) and collapsed to the single resolved client IP when
// the peer is a trusted proxy. The raw inbound chain is preserved on the
// request context and available via OriginalForwardedFor so forensic logging
// keeps seeing what the client actually sent.
func SanitizeForwardHeaders(req *http.Request) *http.Request {
	xff := forwardedFor(req.Header)
	if xff == "" && req.Header.Get("X-Real-Ip") == "" {
		return req
	}

	if xff != "" {
		req = req.WithContext(request.WithValue(req.Context(), originalForwardedForKey, xff))
	}
	req.Header.Del("X-Real-Ip")
	if xff == "" {
		return req
	}

	resolved := ResolveClientIP(req.RemoteAddr, xff, trustedProxies)
	if resolved == PeerHost(req.RemoteAddr) {
		// The resolver fell back to the direct peer: nothing in the
		// forwarded chain is trustworthy.
		req.Header.Del("X-Forwarded-For")
		return req
	}

	req.Header.Set("X-Forwarded-For", resolved)
	return req
}

// OriginalForwardedFor returns the raw inbound X-Forwarded-For chain as it was
// before SanitizeForwardHeaders rewrote it, or "" when there was none.
func OriginalForwardedFor(req *http.Request) string {
	xff, _ := req.Context().Value(originalForwardedForKey).(string)
	return xff
}

type ImpersonationRequest struct {
	ImpersonationConfig *transport.ImpersonationConfig
	InboundUser         *user.Info
	ImpersonatedUser    *user.Info
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
// authoritative correlation id.
func WithRequestID(req *http.Request, id string) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), requestIDKey, id))
}

// RequestID returns the request's authoritative correlation id, or "" when the
// request-id filter has not run.
func RequestID(req *http.Request) string {
	id, _ := req.Context().Value(requestIDKey).(string)
	return id
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

// WithImpersonationConfig returns a copy of parent in which contains the impersonation configuration.
func WithImpersonationConfig(req *http.Request, conf *ImpersonationRequest) *http.Request {
	ctxToReturn := request.WithValue(req.Context(), impersonationConfigKey, conf)
	if *conf.ImpersonatedUser != nil {
		ctxToReturn = request.WithUser(ctxToReturn, *conf.ImpersonatedUser)
	}
	return req.WithContext(ctxToReturn)
}

// ImpersonationConfig returns the impersonation configuration held in the context if existing.
func ImpersonationConfig(req *http.Request) *ImpersonationRequest {
	conf, _ := req.Context().Value(impersonationConfigKey).(*ImpersonationRequest)
	return conf
}

// WithBearerToken will add the bearer token to the request context from an http.Header to the request context.
func WithBearerToken(req *http.Request, header http.Header) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), bearerTokenKey, header.Get("Authorization")))
}

// BearerToken will return the bearer token stored in the request context.
func BearerToken(req *http.Request) string {
	token, _ := req.Context().Value(bearerTokenKey).(string)
	return token
}

// RemoteAddr returns the authoritative source client address for the request.
// The value is resolved once (honouring the configured trusted proxies) and
// cached on the request context so repeated calls within a request are
// consistent and cheap.
func RemoteAddr(req *http.Request) (*http.Request, string) {
	ctx := req.Context()

	clientAddress, ok := ctx.Value(clientAddressKey).(string)
	if !ok {
		clientAddress = ResolveClientIP(req.RemoteAddr, forwardedFor(req.Header), trustedProxies)
		req = req.WithContext(request.WithValue(ctx, clientAddressKey, clientAddress))
	}

	return req, clientAddress
}

// forwardedFor returns the raw X-Forwarded-For header value.
func forwardedFor(headers http.Header) string {
	return headers.Get("X-Forwarded-For")
}

// ResolveClientIP returns the authoritative client IP for a request given the
// peer address, the X-Forwarded-For chain, and the set of trusted proxy
// networks. See the package documentation for the full contract. It is
// IPv4/IPv6 aware and ignores malformed forwarded entries.
//
// This contract is intentionally identical to resolveClientIP in
// pkg/proxy/logging/accesslog.go so the audit-log src_ip and the
// Remote-Client-IP impersonation extra never disagree; the two are duplicated
// only because of package/lane boundaries and MUST be kept in sync until they
// are unified into one shared resolver.
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
