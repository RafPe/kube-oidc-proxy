// Copyright Jetstack Ltd. See LICENSE for details.
package keybundle

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
)

func TestNewSelfSigned(t *testing.T) {
	b, err := NewSelfSigned("127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, []string{"issuer.example"})
	if err != nil {
		t.Fatalf("NewSelfSigned() error = %v", err)
	}

	// cert.GenerateSelfSignedCertKey returns the leaf followed by its CA, so
	// only the first block is the certificate the key belongs to.
	block, _ := pem.Decode(b.CertBytes)
	if block == nil {
		t.Fatal("CertBytes is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	if !b.Key.PublicKey.Equal(leaf.PublicKey) {
		t.Error("Key does not match the certificate's public key")
	}
	if err := leaf.VerifyHostname("issuer.example"); err != nil {
		t.Errorf("certificate does not cover the requested DNS name: %v", err)
	}
}
