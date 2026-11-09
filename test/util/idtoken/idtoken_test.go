// Copyright Jetstack Ltd. See LICENSE for details.
package idtoken

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/rafpe/kube-oidc-proxy/test/util/keybundle"
)

func TestSignRoundTrip(t *testing.T) {
	bundle, err := keybundle.NewSelfSigned("127.0.0.1", nil, nil)
	if err != nil {
		t.Fatalf("NewSelfSigned() error = %v", err)
	}
	issuer := &url.URL{Scheme: "https", Host: "issuer.example"}

	payload, err := NewPayloadForIdentity(issuer, "client", `we"ird\user`, []string{"g1"}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("NewPayloadForIdentity() error = %v", err)
	}

	signed, err := Sign(bundle, payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	jws, err := jose.ParseSigned(signed, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned() error = %v", err)
	}
	verified, err := jws.Verify(&bundle.Key.PublicKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	var claims struct {
		Iss    string   `json:"iss"`
		Aud    []string `json:"aud"`
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
		Exp    int64    `json:"exp"`
	}
	if err := json.Unmarshal(verified, &claims); err != nil {
		t.Fatalf("claims are not JSON: %v", err)
	}
	if claims.Iss != issuer.String() || claims.Email != `we"ird\user` || claims.Exp != 1700000000 ||
		len(claims.Aud) != 2 || claims.Aud[0] != "client" || len(claims.Groups) != 1 {
		t.Errorf("unexpected claims %+v", claims)
	}
}

func TestNewPayloadIsJSON(t *testing.T) {
	issuer := &url.URL{Scheme: "https", Host: "issuer.example"}
	if !json.Valid(NewPayload(issuer, "client", time.Unix(1, 0))) {
		t.Error("NewPayload() is not valid JSON")
	}
}
