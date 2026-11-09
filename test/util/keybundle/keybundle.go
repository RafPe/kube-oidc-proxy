// Copyright Jetstack Ltd. See LICENSE for details.

// Package keybundle generates the self-signed serving certificates and signing
// keys the e2e suite and the metrics demo hand to the mock issuer and the
// proxy.
package keybundle

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"

	"k8s.io/client-go/util/cert"
)

// Bundle is a PEM certificate and its RSA key, both as PEM bytes to mount into
// a pod and, for the key, parsed for signing tokens in-process.
type Bundle struct {
	CertBytes []byte
	KeyBytes  []byte
	Key       *rsa.PrivateKey
}

// NewSelfSigned generates a self-signed certificate and key valid for host and
// the given IPs and DNS names.
func NewSelfSigned(host string, netIPs []net.IP, dnsNames []string) (*Bundle, error) {
	certBytes, keyBytes, err := cert.GenerateSelfSignedCertKey(host, netIPs, dnsNames)
	if err != nil {
		return nil, fmt.Errorf("generating self-signed cert for %s: %w", host, err)
	}

	p, rest := pem.Decode(keyBytes)
	if p == nil {
		return nil, errors.New("generated key is not PEM")
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected trailing data after generated key PEM block: %q", rest)
	}

	key, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing generated key: %w", err)
	}

	return &Bundle{
		CertBytes: certBytes,
		KeyBytes:  keyBytes,
		Key:       key,
	}, nil
}
