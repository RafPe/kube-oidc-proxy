// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/test/util/keybundle"
)

// writeDemoState lays down what up.sh leaves in .state.
func writeDemoState(t *testing.T, dir string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proxyCA, err := keybundle.NewSelfSigned("proxy.example.test", []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"issuer-url":    []byte("https://issuer.proxy.svc.cluster.local:6443\n"),
		"issuer-ca.pem": proxyCA.CertBytes,
		"issuer-key.pem": pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		"proxy-ca.pem": proxyCA.CertBytes,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadStateReadsWhatUpLeftBehind(t *testing.T) {
	dir := t.TempDir()
	writeDemoState(t, dir)

	st, err := loadState(dir)
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	if st.issuerURL.Host != "issuer.proxy.svc.cluster.local:6443" {
		t.Errorf("issuer URL = %s", st.issuerURL)
	}
	if st.kubeconfig != filepath.Join(dir, "kubeconfig") {
		t.Errorf("kubeconfig path = %q", st.kubeconfig)
	}
	if st.issuerBundle.Key == nil || st.proxyCAs == nil || len(st.proxyCAPEM) == 0 {
		t.Error("key material was not loaded")
	}
}

func TestLoadStateNamesTheMissingFile(t *testing.T) {
	_, err := loadState(t.TempDir())
	if err == nil {
		t.Fatal("loadState() on an empty directory returned nil")
	}
	for _, want := range []string{"issuer-url", "make metrics_demo_up"} {
		if !containsString(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestLoadStateRejectsANonPEMKey(t *testing.T) {
	dir := t.TempDir()
	writeDemoState(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "issuer-key.pem"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(dir); err == nil {
		t.Fatal("loadState() accepted a key file that is not PEM")
	}
}

func containsString(s, sub string) bool {
	return len(sub) == 0 || len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
