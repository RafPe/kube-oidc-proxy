// Copyright Jetstack Ltd. See LICENSE for details.

// Package token extracts bearer tokens from HTTP requests.
package token

import (
	"net/http"
	"strings"
)

// ParseFromRequest returns the bearer token from the request's Authorization
// header, stripped of the leading "bearer" scheme. The second return value
// reports whether a non-empty bearer token was present.
func ParseFromRequest(req *http.Request) (string, bool) {
	if req == nil || req.Header == nil {
		return "", false
	}

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
