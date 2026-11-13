// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"net/http"
)

// NewUnauthenticatedHandler returns respond wrapped in the
// failed-authentication audit chain, for a request that failed
// authentication: the event is recorded against the anonymous user.
func NewUnauthenticatedHandler(a *Audit, respond http.HandlerFunc) http.Handler {
	return a.WithUnauthorized(respond)
}

// NewDeniedHandler returns respond wrapped in the ordinary request audit
// chain, for a request that authenticated successfully and is then refused by
// the proxy, whatever status the refusal carries. Unlike
// NewUnauthenticatedHandler the event carries the authenticated identity,
// which the caller MUST have placed in the request context
// (genericapirequest.WithUser) before serving. WithFailedAuthenticationAudit
// is deliberately not used here: it records the event as an authentication
// failure and evaluates the audit policy against an empty user.
func NewDeniedHandler(a *Audit, respond http.HandlerFunc) http.Handler {
	return a.WithRequest(respond)
}
