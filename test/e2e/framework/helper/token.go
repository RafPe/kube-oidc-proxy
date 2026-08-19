// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/test/util"
)

func (h *Helper) NewValidRestConfig(issuerBundle, proxyBundle *util.KeyBundle,
	issuerURL, proxyURL *url.URL, clientID string) (*rest.Config, error) {

	// Valid token with exp in 10 minutes
	tokenPayload := h.NewTokenPayload(issuerURL, clientID,
		time.Now().Add(time.Minute*10))
	signedToken, err := h.SignToken(issuerBundle, tokenPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token %q: %s", tokenPayload, err)
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(proxyBundle.CertBytes); !ok {
		return nil, fmt.Errorf("failed to append proxy cert data to cert pool %s", proxyBundle.CertBytes)
	}

	return &rest.Config{
		Host:        proxyURL.String(),
		Burst:       rest.DefaultBurst,
		BearerToken: signedToken,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}, nil
}

func (h *Helper) SignToken(issuerBundle *util.KeyBundle, tokenPayload []byte) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm("RS256"),
		Key:       issuerBundle.Key,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to initialise new jwt signer: %s", err)
	}

	jwt, err := signer.Sign(tokenPayload)
	if err != nil {
		return "", fmt.Errorf("failed to sign jwt: %s", err)
	}

	signedToken, err := jwt.CompactSerialize()
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// NewTokenPayloadForIdentity returns a token payload for an arbitrary identity,
// for cases that need claims NewTokenPayload's fixed ones cannot express. The
// username goes in the "email" claim and the groups in the "groups" claim,
// matching the --oidc-username-claim/--oidc-groups-claim the suite deploys the
// proxy with. Marshalled rather than formatted so a value containing a quote or
// a backslash cannot produce a malformed (or a differently shaped) token.
func (h *Helper) NewTokenPayloadForIdentity(issuerURL *url.URL, clientID, username string,
	groups []string, exp time.Time) ([]byte, error) {

	payload, err := json.Marshal(map[string]interface{}{
		"iss":    issuerURL.String(),
		"aud":    []string{clientID, "aud-2"},
		"email":  username,
		"groups": groups,
		"exp":    exp.Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token payload: %s", err)
	}

	return payload, nil
}

func (h *Helper) NewTokenPayload(issuerURL *url.URL, clientID string, exp time.Time) []byte {
	// Valid for 10 mins
	return []byte(fmt.Sprintf(`{
	"iss":"%s",
	"aud":["%s","aud-2"],
	"email":"user@example.com",
	"groups":["group-1","group-2"],
	"exp":%d
	}`, issuerURL, clientID, exp.Unix()))
}
