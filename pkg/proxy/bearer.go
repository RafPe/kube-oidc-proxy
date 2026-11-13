// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"net/http"
	"strings"
)

// bearerToken returns the bearer token from the request's Authorization
// header, stripped of the leading "bearer" scheme, for the token-review path.
// The OIDC path does not use it: bearertoken.Authenticator parses the header
// for itself and removes it once a token is accepted. The second return value
// reports whether a non-empty bearer token was present.
func bearerToken(req *http.Request) (string, bool) {
	auth := strings.TrimSpace(req.Header.Get("Authorization"))
	if auth == "" {
		return "", false
	}

	parts := strings.Split(auth, " ")
	if len(parts) < 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", false
	}

	token := parts[1]

	// Empty bearer tokens aren't valid.
	if len(token) == 0 {
		return "", false
	}

	return token, true
}
