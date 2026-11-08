// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/rafpe/kube-oidc-proxy/test/util"
)

// state is what up.sh left in .state: the kubeconfig, the issuer's URL and
// signing key, and the certificate that issued the proxy's serving cert.
type state struct {
	kubeconfig   string
	issuerURL    *url.URL
	issuerBundle *util.KeyBundle
	proxyCAs     *x509.CertPool
	proxyCAPEM   []byte
}

func loadState(dir string) (*state, error) {
	read := func(name string) ([]byte, error) {
		// #nosec G304 -- dir is the operator's own --state flag, and every
		// name is a constant below; this is a developer tool reading the
		// files up.sh just wrote.
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("failed to read %s from %s; run 'make metrics_demo_up' first: %w", name, dir, err)
		}

		return b, nil
	}

	rawURL, err := read("issuer-url")
	if err != nil {
		return nil, err
	}
	issuerURL, err := url.Parse(strings.TrimSpace(string(rawURL)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer-url: %w", err)
	}

	certBytes, err := read("issuer-ca.pem")
	if err != nil {
		return nil, err
	}
	keyBytes, err := read("issuer-key.pem")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("issuer-key.pem is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the issuer key: %w", err)
	}

	proxyCA, err := read("proxy-ca.pem")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(proxyCA) {
		return nil, errors.New("proxy-ca.pem holds no certificate")
	}

	return &state{
		kubeconfig:   filepath.Join(dir, "kubeconfig"),
		issuerURL:    issuerURL,
		issuerBundle: &util.KeyBundle{CertBytes: certBytes, KeyBytes: keyBytes, Key: key},
		proxyCAs:     pool,
		proxyCAPEM:   proxyCA,
	}, nil
}
