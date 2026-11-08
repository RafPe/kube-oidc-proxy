// Copyright Jetstack Ltd. See LICENSE for details.

// The rotation test drives client-go's certificate reload concurrently with
// its own background worker, and client-go's dynamicClientCert reads and
// writes the cached certificate without synchronisation
// (transport/cert_rotation.go loadClientCert). The race detector reports that
// upstream race on every run, so this file is excluded from -race builds; the
// test still runs in every ordinary test run.

//go:build !race

package proxy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/cert"
)

func TestRoundTripperForRestConfigReloadsClientCertificate(t *testing.T) {
	certFile := filepath.Join(t.TempDir(), "client.crt")
	keyFile := filepath.Join(filepath.Dir(certFile), "client.key")
	firstCert, firstKey, err := cert.GenerateSelfSignedCertKey("first-client", nil, nil)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertKey(first-client) error = %v", err)
	}
	secondCert, secondKey, err := cert.GenerateSelfSignedCertKey("second-client", nil, nil)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertKey(second-client) error = %v", err)
	}
	writeProxyClientKeyPair(t, certFile, keyFile, firstCert, firstKey)

	p := &Proxy{}
	roundTripper, err := p.roundTripperForRestConfig(&rest.Config{
		TLSClientConfig: rest.TLSClientConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	})
	if err != nil {
		t.Fatalf("roundTripperForRestConfig() error = %v", err)
	}
	tlsConfig, err := utilnet.TLSClientConfig(roundTripper)
	if err != nil {
		t.Fatalf("TLSClientConfig() error = %v", err)
	}
	if tlsConfig == nil || tlsConfig.GetClientCertificate == nil {
		t.Fatal("roundTripperForRestConfig() has no dynamic client-certificate callback")
	}
	if len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != "http/1.1" {
		t.Errorf("roundTripperForRestConfig() NextProtos = %v, want [http/1.1]", tlsConfig.NextProtos)
	}

	gotFirst, err := tlsConfig.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate(first) error = %v", err)
	}
	writeProxyClientKeyPair(t, certFile, keyFile, secondCert, secondKey)

	// client-go reloads the files on a schedule of its own; poll for the
	// rotation rather than encoding that private interval here.
	rotated := false
	for deadline := time.Now().Add(5 * time.Second); !rotated && time.Now().Before(deadline); {
		gotSecond, err := tlsConfig.GetClientCertificate(nil)
		if err != nil {
			t.Fatalf("GetClientCertificate(second) error = %v", err)
		}
		rotated = !bytes.Equal(gotFirst.Certificate[0], gotSecond.Certificate[0])
		if !rotated {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !rotated {
		t.Error("GetClientCertificate() still returned the original certificate 5s after the files rotated")
	}

	strippedTransport, err := p.roundTripperForRestConfig(&rest.Config{})
	if err != nil {
		t.Fatalf("roundTripperForRestConfig(stripped) error = %v", err)
	}
	strippedTLSConfig, err := utilnet.TLSClientConfig(strippedTransport)
	if err != nil {
		t.Fatalf("TLSClientConfig(stripped) error = %v", err)
	}
	if strippedTLSConfig != nil && strippedTLSConfig.GetClientCertificate != nil {
		t.Error("credential-stripped transport unexpectedly has a client certificate")
	}
}

func writeProxyClientKeyPair(t *testing.T, certFile, keyFile string, certData, keyData []byte) {
	t.Helper()
	if err := os.WriteFile(certFile, certData, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", certFile, err)
	}
	if err := os.WriteFile(keyFile, keyData, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", keyFile, err)
	}
}
