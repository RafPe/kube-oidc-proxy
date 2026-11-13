// Copyright Jetstack Ltd. See LICENSE for details.

// Package idtoken builds and signs the OIDC ID tokens the suite's mock issuer
// vouches for.
package idtoken

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/rafpe/kube-oidc-proxy/test/util/keybundle"
)

// Sign signs payload as an RS256 JWT with the issuer bundle's key and returns
// its compact serialization: a bearer token the mock issuer vouches for.
func Sign(issuerBundle *keybundle.Bundle, payload []byte) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       issuerBundle.Key,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to initialise new jwt signer: %w", err)
	}

	jwt, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign jwt: %w", err)
	}

	signedToken, err := jwt.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize jwt: %w", err)
	}

	return signedToken, nil
}

// DefaultUsername is the identity of the suite's standard token: the user
// the e2e cases bind RBAC to and expect in audit events.
const DefaultUsername = "user@example.com"

// DefaultGroups returns the groups of the suite's standard token. A function
// rather than a variable so no caller can change what another one mints.
func DefaultGroups() []string {
	return []string{"group-1", "group-2"}
}

// NewPayloadForIdentity returns a token payload for an arbitrary identity, for
// cases that need claims NewPayload's fixed ones cannot express. The username
// goes in the "email" claim and the groups in the "groups" claim, matching the
// --oidc-username-claim/--oidc-groups-claim the suite deploys the proxy with.
// Marshalled rather than formatted so a value containing a quote or a
// backslash cannot produce a malformed (or a differently shaped) token.
func NewPayloadForIdentity(issuerURL *url.URL, clientID, username string,
	groups []string, exp time.Time) []byte {

	// json.Marshal only fails on unsupported types and values, and strings, a
	// string slice and an int64 are none of them.
	payload, _ := json.Marshal(map[string]any{
		"iss":    issuerURL.String(),
		"aud":    []string{clientID, "aud-2"},
		"email":  username,
		"groups": groups,
		"exp":    exp.Unix(),
	})

	return payload
}

// NewPayload returns the suite's standard token payload: DefaultUsername in
// DefaultGroups, valid until exp.
func NewPayload(issuerURL *url.URL, clientID string, exp time.Time) []byte {
	return NewPayloadForIdentity(issuerURL, clientID, DefaultUsername, DefaultGroups(), exp)
}
