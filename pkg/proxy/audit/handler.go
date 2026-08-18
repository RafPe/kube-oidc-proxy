// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"net/http"
)

// funcHandler adapts a serve func to http.Handler so it can be wrapped by the
// audit filters. It does not proxy anything; consumers call ServeHTTP when the
// proxy answers a request itself instead of forwarding it.
type funcHandler struct {
	serveFunc func(http.ResponseWriter, *http.Request)
}

// NewUnauthenticatedHandler returns a handler for a request that failed
// authentication. It is expected that consumers of this type will call
// `ServeHTTP` when an unauthenticated request is received.
func NewUnauthenticatedHandler(a *Audit, serveFunc func(http.ResponseWriter, *http.Request)) http.Handler {
	u := &funcHandler{
		serveFunc: serveFunc,
	}

	// if auditor is nil then return without wrapping
	if a == nil {
		return u
	}

	return a.WithUnauthorized(u)
}

// NewForbiddenHandler returns a handler for a request that authenticated
// successfully and is then refused by the proxy. Unlike NewUnauthenticatedHandler
// it audits through the ordinary request chain, so the event carries the
// authenticated identity — which the caller MUST have placed in the request
// context (genericapirequest.WithUser) before serving. WithFailedAuthenticationAudit
// is deliberately not used here: it records the event as an authentication
// failure and evaluates the audit policy against an empty user.
func NewForbiddenHandler(a *Audit, serveFunc func(http.ResponseWriter, *http.Request)) http.Handler {
	h := &funcHandler{
		serveFunc: serveFunc,
	}

	// if auditor is nil then return without wrapping
	if a == nil {
		return h
	}

	return a.WithRequest(h)
}

func (u *funcHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	u.serveFunc(rw, r)
}
