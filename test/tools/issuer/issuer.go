// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
)

type issuer struct {
	issuerURL         string
	keyFile, certFile string

	sk *rsa.PrivateKey

	stopCh <-chan struct{}
}

func newIssuer(issuerURL, keyFile, certFile string, stopCh <-chan struct{}) (*issuer, error) {
	b, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil,
			fmt.Errorf("failed to parse PEM block containing the key: %q", keyFile)
	}

	sk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &issuer{
		keyFile:   keyFile,
		certFile:  certFile,
		issuerURL: issuerURL,
		sk:        sk,
		stopCh:    stopCh,
	}, nil
}

func (i *issuer) Run(bindAddress, listenPort string) (<-chan struct{}, error) {
	serveAddr := fmt.Sprintf("%s:%s", bindAddress, listenPort)

	l, err := net.Listen("tcp", serveAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		<-i.stopCh
		if l != nil {
			l.Close()
		}
	}()

	compCh := make(chan struct{})
	go func() {
		defer close(compCh)

		err := http.ServeTLS(l, i, i.certFile, i.keyFile)
		if err != nil {
			slog.Error("mock issuer: stopped serving TLS", slog.String("address", serveAddr), slog.Any("error", err))
		}
	}()

	slog.Info("mock issuer: listening and serving", slog.String("address", serveAddr))

	return compCh, nil
}

func (i *issuer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	slog.Info("mock issuer: received request", slog.String("url", r.URL.String()))

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	switch r.URL.String() {
	case "/.well-known/openid-configuration":
		rw.WriteHeader(http.StatusOK)

		if _, err := rw.Write(i.wellKnownResponse()); err != nil {
			slog.Error("mock issuer: failed to write openid-configuration response", slog.Any("error", err))
		}

	case "/certs":
		rw.WriteHeader(http.StatusOK)

		certsDiscovery := i.certsDiscovery()
		if _, err := rw.Write(certsDiscovery); err != nil {
			slog.Error("mock issuer: failed to write certificate discovery response", slog.Any("error", err))
		}

	default:
		slog.Error("mock issuer: unexpected URL request", slog.String("url", r.URL.String()))
		rw.WriteHeader(http.StatusNotFound)
		if _, err := rw.Write([]byte("{}\n")); err != nil {
			slog.Error("mock issuer: failed to write data to response", slog.Any("error", err))
		}
	}
}

func (i *issuer) wellKnownResponse() []byte {
	return []byte(fmt.Sprintf(`{
 "issuer": "%s",
 "jwks_uri": "%s/certs",
 "subject_types_supported": [
  "public"
 ],
 "id_token_signing_alg_values_supported": [
  "RS256"
 ],
 "scopes_supported": [
  "openid",
  "email"
 ],
 "token_endpoint_auth_methods_supported": [
  "client_secret_post",
  "client_secret_basic"
 ],
 "claims_supported": [
  "email",
	"e2e-username-claim",
	"e2e-groups-claim",
  "sub"
 ],
 "code_challenge_methods_supported": [
  "plain",
  "S256"
 ]
}`, i.issuerURL, i.issuerURL))
}

func (i *issuer) certsDiscovery() []byte {
	n := base64.RawURLEncoding.EncodeToString(i.sk.N.Bytes())

	return []byte(fmt.Sprintf(`{
	  "keys": [
	    {
	      "kid": "0905d6f9cd9b0f1f852e8b207e8f673abca4bf75",
	      "e": "AQAB",
	      "kty": "RSA",
	      "alg": "RS256",
	      "n": "%s",
	      "use": "sig"
	    }
	  ]
	}`, n))
}
