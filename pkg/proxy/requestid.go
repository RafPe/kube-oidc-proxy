// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"net"
	"net/http"
	"strings"
	"unicode"

	"k8s.io/apimachinery/pkg/util/uuid"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
)

const (
	headerAuditID   = "Audit-ID"
	headerRequestID = "X-Request-ID"
	maxRequestIDLen = 64
)

// withRequestID is the outermost request filter. It decides the request's
// identity before authentication, audit, or logging can see it, and puts that
// identity in the Audit-ID request header: the vendored withAuditInit reads only
// the header and overwrites any context value, so the header is the one channel
// both audit chains and the upstream API server honour.
func (p *Proxy) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inbound := validRequestID(r.Header.Get(headerAuditID))
		if inbound == "" {
			inbound = validRequestID(r.Header.Get(headerRequestID))
		}

		id := string(uuid.NewUUID())
		if inbound != "" {
			r = context.WithClientRequestID(r, inbound)
			if peerIsTrusted(r.RemoteAddr, p.trustedProxies) {
				id = inbound
			}
		}

		r.Header.Set(headerAuditID, id)
		r.Header.Del(headerRequestID)
		w.Header().Set(headerAuditID, id)
		next.ServeHTTP(w, context.WithRequestID(r, id))
	})
}

// validRequestID accepts printable ASCII without spaces, at most
// maxRequestIDLen bytes; anything else is treated as absent.
func validRequestID(v string) string {
	if v == "" || len(v) > maxRequestIDLen {
		return ""
	}
	for _, r := range v {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return ""
		}
	}
	return strings.TrimSpace(v)
}

// peerIsTrusted reports whether the immediate peer is inside one of the
// configured trusted-proxy networks. Only such a peer may choose the request's
// correlation id; for anyone else the inbound value is kept as
// client_request_id and the proxy mints its own.
func peerIsTrusted(remoteAddr string, trusted []*net.IPNet) bool {
	return context.IPInNetworks(context.PeerHost(remoteAddr), trusted)
}
