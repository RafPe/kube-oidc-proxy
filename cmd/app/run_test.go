// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/client-go/util/cert"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "auth-config-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing temp file: %v", err)
	}
	return f.Name()
}

func TestOIDCAutherFromJWT_Construction(t *testing.T) {
	emptyPrefix := ""
	entry := apiserverapi.JWTAuthenticator{
		Issuer: apiserverapi.Issuer{
			URL:       "https://vault.example.com/v1/identity/oidc",
			Audiences: []string{"my-client"},
		},
		ClaimMappings: apiserverapi.ClaimMappings{
			Username: apiserverapi.PrefixedClaimOrExpression{
				Claim:  "email",
				Prefix: &emptyPrefix,
			},
			Groups: apiserverapi.PrefixedClaimOrExpression{
				Claim:  "groups",
				Prefix: &emptyPrefix,
			},
		},
		UserValidationRules: []apiserverapi.UserValidationRule{
			{Expression: "!user.username.startsWith('system:')", Message: "no system: prefix"},
		},
	}

	auther, err := oidcAutherFromJWT(
		entry,
		authenticationcel.NewDefaultCompiler(),
		[]string{"RS256"},
		&options.OIDCAuthenticationOptions{},
	)
	if err != nil {
		t.Fatalf("oidcAutherFromJWT() unexpected error: %v", err)
	}
	if auther == nil {
		t.Error("oidcAutherFromJWT() returned nil authenticator")
	}
}

func TestOIDCHTTPClientReloadsClientCertificate(t *testing.T) {
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
	writeClientKeyPair(t, certFile, keyFile, firstCert, firstKey)

	client, err := oidcHTTPClient("", nil, certFile, keyFile)
	if err != nil {
		t.Fatalf("oidcHTTPClient(%q, %q) error = %v", certFile, keyFile, err)
	}
	tlsConfig, err := utilnet.TLSClientConfig(client.Transport)
	if err != nil {
		t.Fatalf("TLSClientConfig() error = %v", err)
	}
	if tlsConfig == nil || tlsConfig.GetClientCertificate == nil {
		t.Fatal("oidcHTTPClient() transport has no dynamic client-certificate callback")
	}

	gotFirst, err := tlsConfig.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate(first) error = %v", err)
	}
	writeClientKeyPair(t, certFile, keyFile, secondCert, secondKey)
	time.Sleep(1100 * time.Millisecond)
	gotSecond, err := tlsConfig.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate(second) error = %v", err)
	}
	if bytes.Equal(gotFirst.Certificate[0], gotSecond.Certificate[0]) {
		t.Error("GetClientCertificate() returned the original certificate after files rotated")
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

func TestJWTAuthenticatorFromOIDCOptions_RequiredClaims(t *testing.T) {
	t.Run("required claims are mapped into ClaimValidationRules", func(t *testing.T) {
		o := &options.OIDCAuthenticationOptions{
			IssuerURL:     "https://vault.example.com",
			ClientID:      "my-client",
			UsernameClaim: "email",
			GroupsClaim:   "groups",
			SigningAlgs:   []string{"RS256"},
			RequiredClaims: map[string]string{
				"hd":   "example.com",
				"team": "platform",
			},
		}

		got := jwtAuthenticatorFromOIDCOptions(o)

		// Sorted by claim name for deterministic construction.
		want := []apiserverapi.ClaimValidationRule{
			{Claim: "hd", RequiredValue: "example.com"},
			{Claim: "team", RequiredValue: "platform"},
		}
		if !reflect.DeepEqual(got.ClaimValidationRules, want) {
			t.Errorf("ClaimValidationRules = %#v, want %#v", got.ClaimValidationRules, want)
		}
	})

	t.Run("no required claims yields no rules", func(t *testing.T) {
		o := &options.OIDCAuthenticationOptions{
			IssuerURL:     "https://vault.example.com",
			ClientID:      "my-client",
			UsernameClaim: "email",
			GroupsClaim:   "groups",
			SigningAlgs:   []string{"RS256"},
		}

		got := jwtAuthenticatorFromOIDCOptions(o)
		if len(got.ClaimValidationRules) != 0 {
			t.Errorf("ClaimValidationRules = %#v, want empty", got.ClaimValidationRules)
		}
	})
}

func TestBuildTokenAuther_SingleIssuer(t *testing.T) {
	opts := &options.Options{
		OIDCAuthentication: &options.OIDCAuthenticationOptions{
			IssuerURL:     "https://vault.example.com/v1/identity/oidc",
			ClientID:      "my-client",
			UsernameClaim: "email",
			GroupsClaim:   "groups",
			SigningAlgs:   []string{"RS256"},
		},
		AuthenticationConfig: &options.AuthenticationConfigOptions{},
	}

	auther, issuerURLs, err := buildTokenAuther(opts, discardLogger(), discardLogger())
	if err != nil {
		t.Fatalf("buildTokenAuther() unexpected error: %v", err)
	}
	if auther == nil {
		t.Error("buildTokenAuther() returned nil authenticator")
	}
	if want := []string{opts.OIDCAuthentication.IssuerURL}; len(issuerURLs) != len(want) || issuerURLs[0] != want[0] {
		t.Errorf("buildTokenAuther() issuerURLs = %v, want %v", issuerURLs, want)
	}
}

func TestBuildTokenAuther_AuthConfig(t *testing.T) {
	configContent := `
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://vault.example.com/v1/identity/oidc
      audiences:
        - my-client
    claimMappings:
      username:
        claim: email
        prefix: ""
      groups:
        claim: groups
        prefix: ""
  - issuer:
      url: https://issuer2.example.com/v1/identity/oidc
      audiences:
        - kubernetes
    claimMappings:
      username:
        claim: email
        prefix: ""
      groups:
        claim: groups
        prefix: ""
`
	configPath := writeTempFile(t, configContent)

	opts := &options.Options{
		OIDCAuthentication: &options.OIDCAuthenticationOptions{
			SigningAlgs: []string{"RS256"},
		},
		AuthenticationConfig: &options.AuthenticationConfigOptions{
			ConfigFile: configPath,
		},
	}

	auther, issuerURLs, err := buildTokenAuther(opts, discardLogger(), discardLogger())
	if err != nil {
		t.Fatalf("buildTokenAuther() unexpected error: %v", err)
	}
	if auther == nil {
		t.Error("buildTokenAuther() returned nil authenticator")
	}
	want := []string{
		"https://vault.example.com/v1/identity/oidc",
		"https://issuer2.example.com/v1/identity/oidc",
	}
	if len(issuerURLs) != len(want) {
		t.Fatalf("buildTokenAuther() issuerURLs = %v, want %v", issuerURLs, want)
	}
	for i := range want {
		if issuerURLs[i] != want[i] {
			t.Errorf("buildTokenAuther() issuerURLs[%d] = %q, want %q", i, issuerURLs[i], want[i])
		}
	}
}

func TestBuildUnionAutherFromV1ConfigWithCEL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.yaml")
	cfg := `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
    groups:
      expression: '["g:" + claims.owner]'
- issuer:
    url: https://issuer2.example.com
    audiences: ["aud-two"]
  claimMappings:
    username:
      claim: sub
      prefix: "two:"
`
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}

	opts := options.New()
	opts.AuthenticationConfig.ConfigFile = path

	auther, issuerURLs, err := buildTokenAuther(opts, discardLogger(), discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auther == nil {
		t.Fatal("expected a token authenticator, got nil")
	}
	want := []string{"https://issuer1.example.com", "https://issuer2.example.com"}
	if !reflect.DeepEqual(issuerURLs, want) {
		t.Fatalf("expected issuer URLs %v, got %v", want, issuerURLs)
	}
}

func TestBuildTokenAuther_AuthConfig_InvalidFile(t *testing.T) {
	opts := &options.Options{
		OIDCAuthentication:   &options.OIDCAuthenticationOptions{SigningAlgs: []string{"RS256"}},
		AuthenticationConfig: &options.AuthenticationConfigOptions{ConfigFile: "/does/not/exist.yaml"},
	}

	_, _, err := buildTokenAuther(opts, discardLogger(), discardLogger())
	if err == nil {
		t.Error("buildTokenAuther() expected error for missing config file, got nil")
	}
}

func TestCheckReservedIdentityPrefixes(t *testing.T) {
	tests := map[string]struct {
		usernamePrefix string
		groupsPrefix   string
		configFile     string
		wantErr        bool
	}{
		"no prefixes": {},
		"ordinary prefixes": {
			usernamePrefix: "oidc:",
			groupsPrefix:   "oidc:",
		},
		"reserved username prefix": {
			usernamePrefix: "system:",
			wantErr:        true,
		},
		"reserved groups prefix": {
			groupsPrefix: "system:serviceaccount:",
			wantErr:      true,
		},
		// --oidc-* prefixes are ignored entirely when an authentication
		// configuration file is in use, so they must not fail startup.
		"reserved prefix ignored in multi-issuer mode": {
			usernamePrefix: "system:",
			configFile:     "/etc/kube-oidc-proxy/authentication.yaml",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			opts := &options.Options{
				OIDCAuthentication: &options.OIDCAuthenticationOptions{
					UsernamePrefix: test.usernamePrefix,
					GroupsPrefix:   test.groupsPrefix,
				},
				AuthenticationConfig: &options.AuthenticationConfigOptions{ConfigFile: test.configFile},
				App:                  &options.KubeOIDCProxyOptions{},
			}

			err := checkReservedIdentityPrefixes(opts)

			if test.wantErr && err == nil {
				t.Error("checkReservedIdentityPrefixes() = nil, want an error")
			}
			if !test.wantErr && err != nil {
				t.Errorf("checkReservedIdentityPrefixes() = %v, want nil", err)
			}
		})
	}
}

// discardLogger is the logger the buildTokenAuther cases pass: these tests
// exercise authenticator construction, not the records it emits.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
