// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// ErrAudienceUnrouted is the error for a token whose iss has several issuers
// and whose aud selects none or more than one of them. The text contains no
// token content.
var ErrAudienceUnrouted = errors.New("oidc: the token audience selects no single issuer")

// legacyGoogleIssuer is the iss value that Google used before it added the
// scheme. The upstream authenticator reads it as googleIssuer.
const (
	legacyGoogleIssuer = "accounts.google.com"
	googleIssuer       = "https://accounts.google.com"
)

// route is one issuer of a router.
type route struct {
	url           string
	audiences     []string
	authenticator authenticator.Token
}

// router is the token authenticator of the proxy. It selects at most one
// issuer for a token and runs the verification of that issuer only. ADR-0001
// (docs/decisions/0001-route-same-issuer-entries-by-audience.md) gives the
// rules.
type router struct {
	byURL map[string][]route
}

// newRouter returns a router over routes. The routes of one issuer URL must
// have disjoint audiences. LoadConfiguration makes sure of this.
func newRouter(routes []route) *router {
	r := &router{byURL: make(map[string][]route, len(routes))}
	for _, rt := range routes {
		r.byURL[rt.url] = append(r.byURL[rt.url], rt)
	}
	return r
}

// AuthenticateToken selects an issuer by the iss and aud claims of token, and
// returns the result of that issuer unchanged. It reads the claims without
// verification. The claims only select the issuer. The selected issuer then
// verifies the full token.
//
//   - A token that is not a compact JWT, or an iss with no issuer: ok is
//     false and the error is nil.
//   - An iss with one issuer: that issuer verifies the token. The aud claim
//     has no effect on the selection.
//   - An iss with several issuers: the issuer whose audiences contain a value
//     of aud verifies the token. If no issuer or more than one issuer
//     matches, the error is ErrAudienceUnrouted and no issuer runs.
func (r *router) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	claims, err := parseUntrustedClaims(token)
	if err != nil {
		return nil, false, nil
	}
	routes := r.byURL[claims.issuer]
	switch len(routes) {
	case 0:
		return nil, false, nil
	case 1:
		return routes[0].authenticator.AuthenticateToken(ctx, token)
	}

	audiences, err := claims.audiences()
	if err != nil {
		return nil, false, ErrAudienceUnrouted
	}
	var selected *route
	for i := range routes {
		if !slices.ContainsFunc(audiences, func(a string) bool { return slices.Contains(routes[i].audiences, a) }) {
			continue
		}
		if selected != nil {
			return nil, false, ErrAudienceUnrouted
		}
		selected = &routes[i]
	}
	if selected == nil {
		return nil, false, ErrAudienceUnrouted
	}
	return selected.authenticator.AuthenticateToken(ctx, token)
}

// untrustedClaims are the iss and aud claims of a token before verification.
// Do not use them for an access decision.
type untrustedClaims struct {
	issuer string
	aud    json.RawMessage
}

// parseUntrustedClaims reads the iss and aud claims of a compact JWT without
// verification. It reads iss as the upstream untrustedIssuer function does,
// so the router and the upstream authenticator agree on the issuer of every
// token.
func parseUntrustedClaims(token string) (untrustedClaims, error) {
	if strings.HasPrefix(strings.TrimSpace(token), "{") {
		return untrustedClaims{}, errors.New("token is not compact JWT")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return untrustedClaims{}, errors.New("malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return untrustedClaims{}, err
	}
	var raw struct {
		Issuer string          `json:"iss"`
		Aud    json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return untrustedClaims{}, err
	}
	if raw.Issuer == legacyGoogleIssuer {
		raw.Issuer = googleIssuer
	}
	return untrustedClaims{issuer: raw.Issuer, aud: raw.Aud}, nil
}

// audiences returns the aud claim as a list. A JWT aud is one string or an
// array of strings. Any other value is an error.
func (c untrustedClaims) audiences() ([]string, error) {
	var one string
	if err := json.Unmarshal(c.aud, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(c.aud, &many); err != nil {
		return nil, err
	}
	return many, nil
}
