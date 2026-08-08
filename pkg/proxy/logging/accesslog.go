// Copyright Jetstack Ltd. See LICENSE for details.

// Package logging emits structured, sanitized access logs for proxied and
// failed requests.
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
// with SetTrustedProxies. The raw forwarded chain is still emitted for
// observability under the explicitly-untrusted "forwarded_for_untrusted" field
// and must not be treated as identity.
package logging

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"unicode"

	"k8s.io/apiserver/pkg/authentication/user"
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
	"originaluser.jetstack.io-extra":  {},
}

// logger is the structured logger used for access logs. It defaults to a JSON
// handler writing to stdout, preserving the previous stdout destination while
// giving deterministic, injection-safe encoding. Tests redirect it with
// SetLogger.
var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

// trustedProxies holds the networks whose forwarded headers are honoured when
// resolving the client IP. Empty (the default) means no proxy is trusted.
var trustedProxies []*net.IPNet

// SetLogger overrides the structured logger used for access logs. A nil logger
// is ignored. Intended for wiring and tests.
func SetLogger(l *slog.Logger) {
	if l != nil {
		logger = l
	}
}

// SetTrustedProxies configures the trusted-proxy networks used when resolving
// the client IP from forwarded headers. Passing nil (the default) disables
// forwarded-header trust entirely.
func SetTrustedProxies(nets []*net.IPNet) {
	trustedProxies = nets
}

// LogSuccessfulRequest logs a successfully authenticated and proxied request as
// a single structured record.
func LogSuccessfulRequest(req *http.Request, inboundUser user.Info, outboundUser user.Info) {
	attrs := requestAttrs("AuSuccess", req)
	attrs = append(attrs, userAttrs("inbound", inboundUser)...)
	if outboundUser != nil {
		attrs = append(attrs, userAttrs("outbound", outboundUser)...)
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "proxied request", attrs...)
}

// LogFailedRequest logs a request that failed authentication or authorization.
func LogFailedRequest(req *http.Request) {
	logger.LogAttrs(context.Background(), slog.LevelInfo, "rejected request",
		requestAttrs("AuFail", req)...)
}

// requestAttrs builds the request-scoped structured fields shared by successful
// and failed logs. src_ip is the authoritative resolved client IP;
// forwarded_for_untrusted is the raw, sanitized forwarded chain and is not
// identity.
func requestAttrs(event string, req *http.Request) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("event", event),
		slog.String("src_ip", resolveClientIP(req.RemoteAddr, forwardedFor(req.Header), trustedProxies)),
		slog.String("path", sanitizePath(req)),
	}
	if fwd := sanitize(forwardedFor(req.Header)); fwd != "" {
		attrs = append(attrs, slog.String("forwarded_for_untrusted", fwd))
	}
	return attrs
}

// userAttrs renders a user.Info as sanitized, structured fields under the given
// prefix. Only allowlisted extras are logged; the number of omitted claim keys
// is reported so operators can tell data was dropped.
func userAttrs(prefix string, u user.Info) []slog.Attr {
	attrs := []slog.Attr{
		slog.String(prefix+"_user", sanitize(u.GetName())),
		slog.Any(prefix+"_groups", sanitizeSlice(u.GetGroups())),
	}
	if uid := u.GetUID(); uid != "" {
		attrs = append(attrs, slog.String(prefix+"_uid", sanitize(uid)))
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
// safe to log and a count of the omitted (non-allowlisted) keys.
func loggableExtras(extra map[string][]string) (map[string][]string, int) {
	if len(extra) == 0 {
		return nil, 0
	}
	safe := make(map[string][]string)
	omitted := 0
	for k, v := range extra {
		if _, ok := loggableExtraKeys[k]; ok {
			safe[sanitize(k)] = sanitizeSlice(v)
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
	return sanitize(req.URL.Path)
}

// sanitize removes control characters from a user-controlled string so that
// values cannot inject newlines or terminal escapes into the log stream. Tabs,
// carriage returns and newlines collapse to a single space; other control
// runes are dropped.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// sanitizeSlice sanitizes every element of a slice, returning a fresh slice.
func sanitizeSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = sanitize(v)
	}
	return out
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
	peer := peerHost(remoteAddr)

	// Without trust, or when the peer itself is not a trusted proxy, forwarded
	// headers are ignored entirely: the direct peer is the client.
	if xff == "" || !ipInNetworks(peer, trusted) {
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
		if ipInNetworks(ip, trusted) {
			continue
		}
		return ip
	}

	return peer
}

// peerHost extracts the host portion of a host:port peer address, IPv6-safe. It
// falls back to the raw value when the address has no port (some call sites
// build requests without a RemoteAddr).
func peerHost(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// ipInNetworks reports whether ip parses and falls within any of the networks.
func ipInNetworks(ip string, networks []*net.IPNet) bool {
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
