// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/test/util/idtoken"
	"github.com/rafpe/kube-oidc-proxy/test/util/keybundle"
)

// NewValidRestConfig returns a client-go configuration that reaches the proxy
// at proxyURL with a freshly signed token for the suite's standard identity,
// trusting the proxy's serving certificate.
func (h *Helper) NewValidRestConfig(issuerBundle, proxyBundle *keybundle.Bundle,
	issuerURL, proxyURL *url.URL, clientID string) (*rest.Config, error) {

	// Valid token with exp in 10 minutes
	tokenPayload := idtoken.NewPayload(issuerURL, clientID,
		time.Now().Add(time.Minute*10))
	signedToken, err := idtoken.Sign(issuerBundle, tokenPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token %q: %w", tokenPayload, err)
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
