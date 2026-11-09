// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"net/http"
	"unicode"

	"k8s.io/apimachinery/pkg/util/uuid"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/clientip"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
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
//
// The id also goes on the context (never bound onto a logger with With), so
// Emit can supply request_id to any event that requires it however deep in the
// chain the call site sits.
func (p *Proxy) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inbound := validRequestID(r.Header.Get(headerAuditID))
		if inbound == "" {
			inbound = validRequestID(r.Header.Get(headerRequestID))
		}

		id := string(uuid.NewUUID())
		if inbound != "" {
			r = reqctx.WithClientRequestID(r, inbound)
			// Only a trusted proxy may choose the request's correlation
			// id; for anyone else the inbound value is kept as
			// client_request_id and the proxy mints its own.
			if clientip.PeerTrusted(r.RemoteAddr, p.trustedProxies) {
				id = inbound
			}
		}

		r.Header.Set(headerAuditID, id)
		r.Header.Del(headerRequestID)
		w.Header().Set(headerAuditID, id)

		next.ServeHTTP(w, reqctx.WithRequestID(r, id))
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
	return v
}
