// Copyright Jetstack Ltd. See LICENSE for details.

// Package clientip is the proxy's trusted-proxy contract: which address a
// request is attributed to, and which forwarding headers may say otherwise
// (see issue #56).
//
// The immediate peer (req.RemoteAddr) is always authoritative for the client
// IP. X-Forwarded-For is honoured ONLY to the extent that the hops closest to
// the proxy are themselves within a configured trusted-proxy network: the chain
// is walked right-to-left, trusted hops are skipped, and the first untrusted
// address is taken as the client. When no trusted proxies are configured (the
// default), forwarded headers are never trusted and the direct peer is used, so
// an untrusted client cannot spoof its resolved IP.
//
// Only X-Forwarded-For is parsed; the RFC 7239 Forwarded header is not honoured.
// On a malformed forwarded hop, or when the entire chain is itself trusted, the
// direct peer is returned.
//
// The trusted networks are passed in by the caller that owns them; this package
// holds no process-wide state.
package clientip

import (
	"net"
	"strings"
)

// The inbound forwarding headers the contract owns. They are exported so every
// reader of the headers spells them the same way.
const (
	HeaderForwardedFor = "X-Forwarded-For"
	HeaderRealIP       = "X-Real-Ip"
)

// Resolve returns the authoritative client IP for a request given the peer
// address, the X-Forwarded-For chain, and the trusted proxy networks. It is
// IPv4/IPv6 aware and ignores malformed forwarded entries.
func Resolve(remoteAddr, xff string, trusted []*net.IPNet) string {
	peer := PeerHost(remoteAddr)

	// Without trust, or when the peer itself is not a trusted proxy, forwarded
	// headers are ignored entirely: the direct peer is the client.
	if xff == "" || !InNetworks(peer, trusted) {
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
		if InNetworks(ip, trusted) {
			continue
		}
		return ip
	}

	return peer
}

// PeerTrusted reports whether the immediate peer is itself a trusted proxy,
// the condition under which anything it forwards on a client's behalf may be
// believed.
func PeerTrusted(remoteAddr string, trusted []*net.IPNet) bool {
	return InNetworks(PeerHost(remoteAddr), trusted)
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

// InNetworks reports whether ip parses and falls within any of the networks.
func InNetworks(ip string, networks []*net.IPNet) bool {
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
