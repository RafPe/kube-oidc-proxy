// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/client-go/util/cert"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

// selfSignedCA returns a PEM certificate usable as an issuer CA.
func selfSignedCA(t *testing.T) []byte {
	t.Helper()
	certData, _, err := cert.GenerateSelfSignedCertKey("issuer-ca", nil, nil)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertKey() error = %v", err)
	}
	return certData
}

// TestCAContentProviderInlineCertificateAuthority pins the document's inline
// CA branch: valid PEM becomes the bundle the authenticator verifies the
// issuer with, and anything else is refused at construction.
func TestCAContentProviderInlineCertificateAuthority(t *testing.T) {
	t.Run("valid PEM is served as the bundle", func(t *testing.T) {
		ca := selfSignedCA(t)
		provider, err := caContentProvider(documentIssuer(string(ca)), discardLogger())
		if err != nil {
			t.Fatalf("caContentProvider() error = %v", err)
		}
		if provider == nil {
			t.Fatal("caContentProvider() = nil, want the inline CA")
		}
		if got := provider.CurrentCABundleContent(); string(got) != string(ca) {
			t.Errorf("CurrentCABundleContent() = %q, want the inline PEM", got)
		}
	})

	t.Run("invalid PEM is refused", func(t *testing.T) {
		_, err := caContentProvider(documentIssuer("not a certificate"), discardLogger())
		if err == nil || !strings.Contains(err.Error(), "invalid certificateAuthority") {
			t.Fatalf("caContentProvider() error = %v, want the invalid certificateAuthority refusal", err)
		}
		_, err = newIssuerAuthenticator(documentIssuer("not a certificate"), authenticationcel.NewDefaultCompiler(), Config{}, discardLogger())
		if err == nil || !strings.Contains(err.Error(), "invalid certificateAuthority") {
			t.Fatalf("newIssuerAuthenticator() error = %v, want the invalid certificateAuthority refusal", err)
		}
	})

	t.Run("no CA means the system roots", func(t *testing.T) {
		provider, err := caContentProvider(documentIssuer(""), discardLogger())
		if err != nil || provider != nil {
			t.Fatalf("caContentProvider() = %v, %v; want nil, nil", provider, err)
		}
	})
}

// TestCAFileUnreadableIsReported pins the only signal an operator gets when
// the --oidc-ca-file becomes unreadable after startup: the bundle is re-read on
// every use, comes back empty, and a proxy.config.invalid record names why.
func TestCAFileUnreadableIsReported(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)

	path := filepath.Join(t.TempDir(), "ca.crt")
	ca := selfSignedCA(t)
	if err := os.WriteFile(path, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := caContentProvider(issuer{caFile: path}, logging.ForComponent(root, logging.ComponentStartup))
	if err != nil {
		t.Fatalf("caContentProvider() error = %v", err)
	}

	if got := provider.CurrentCABundleContent(); string(got) != string(ca) {
		t.Fatalf("CurrentCABundleContent() = %q, want the file's PEM", got)
	}
	if raw := cap.Raw(); raw != "" {
		t.Fatalf("a readable CA file emitted records: %s", raw)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := provider.CurrentCABundleContent(); len(got) != 0 {
		t.Errorf("CurrentCABundleContent() = %q, want empty for an unreadable file", got)
	}
	rec := cap.Only(t, logging.EventProxyConfigInvalid)
	if rec.String("reason") != string(reasonCAFileUnreadable) {
		t.Errorf("reason = %q, want %q", rec.String("reason"), reasonCAFileUnreadable)
	}
	if rec.String("error_message") == "" {
		t.Error("error_message must carry why the file could not be read")
	}
	if rec.String("component") != string(logging.ComponentStartup) {
		t.Errorf("component = %q, want startup", rec.String("component"))
	}
}

func TestOIDCHTTPClientPresentsAReloadingClientCertificate(t *testing.T) {
	certFile := filepath.Join(t.TempDir(), "client.crt")
	keyFile := filepath.Join(filepath.Dir(certFile), "client.key")
	certData, keyData, err := cert.GenerateSelfSignedCertKey("client", nil, nil)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertKey() error = %v", err)
	}
	writeClientKeyPair(t, certFile, keyFile, certData, keyData)

	client, err := oidcHTTPClient("", nil, certFile, keyFile)
	if err != nil {
		t.Fatalf("oidcHTTPClient(%q, %q) error = %v", certFile, keyFile, err)
	}
	tlsConfig, err := utilnet.TLSClientConfig(client.Transport)
	if err != nil {
		t.Fatalf("TLSClientConfig() error = %v", err)
	}
	// client-go reloads the files behind this callback; the rotation itself
	// is pinned where the proxy's own transport is built, in pkg/proxy.
	if tlsConfig == nil || tlsConfig.GetClientCertificate == nil {
		t.Fatal("oidcHTTPClient() transport has no dynamic client-certificate callback")
	}
	if client.Timeout != oidcHTTPTimeout {
		t.Fatalf("client timeout = %s, want %s", client.Timeout, oidcHTTPTimeout)
	}
}

func writeClientKeyPair(t *testing.T, certFile, keyFile string, certData, keyData []byte) {
	t.Helper()
	if err := os.WriteFile(certFile, certData, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", certFile, err)
	}
	if err := os.WriteFile(keyFile, keyData, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", keyFile, err)
	}
}
