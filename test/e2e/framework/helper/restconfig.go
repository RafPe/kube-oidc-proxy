// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/test/util/keybundle"
)

// NewValidRestConfig returns a client-go configuration that reaches the proxy
// at proxyURL with bearerToken, trusting the proxy's serving certificate.
func (h *Helper) NewValidRestConfig(proxyBundle *keybundle.Bundle, proxyURL *url.URL,
	bearerToken string) (*rest.Config, error) {

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(proxyBundle.CertBytes); !ok {
		return nil, fmt.Errorf("failed to append proxy cert data to cert pool %s", proxyBundle.CertBytes)
	}

	return &rest.Config{
		Host:        proxyURL.String(),
		Burst:       rest.DefaultBurst,
		BearerToken: bearerToken,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}, nil
}
