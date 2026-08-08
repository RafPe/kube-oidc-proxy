// Copyright Jetstack Ltd. See LICENSE for details.

// Package token provides helpers for extracting bearer tokens from HTTP
// requests and for generating fake JWTs used to probe issuer readiness.
package token

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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

// FakeJWT generates a valid JWT for the given issuer URL, signed with a
// generated key. It is useful for probing whether an issuer's authenticator has
// completed its signer initialization.
func FakeJWT(issuerURL string) (string, error) {
	key := []byte("this-is-a-32-byte-long-secret-key!!!!")

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}

	cl := jwt.Claims{
		Subject:   "fake",
		Issuer:    issuerURL,
		NotBefore: jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
		Audience:  jwt.Audience(nil),
	}

	return jwt.Signed(sig).Claims(cl).Serialize()
}
