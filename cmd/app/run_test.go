// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"os"
	"testing"

	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"

	"github.com/jetstack/kube-oidc-proxy/cmd/app/options"
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
	entry := apiserverv1beta1.JWTAuthenticator{
		Issuer: apiserverv1beta1.Issuer{
			URL:       "https://vault.example.com/v1/identity/oidc",
			Audiences: []string{"my-client"},
		},
		ClaimMappings: apiserverv1beta1.ClaimMappings{
			Username: apiserverv1beta1.PrefixedClaimOrExpression{
				Claim:  "email",
				Prefix: &emptyPrefix,
			},
			Groups: apiserverv1beta1.PrefixedClaimOrExpression{
				Claim:  "groups",
				Prefix: &emptyPrefix,
			},
		},
		UserValidationRules: []apiserverv1beta1.UserValidationRule{
			{Expression: "!user.username.startsWith('system:')", Message: "no system: prefix"},
		},
	}

	auther, err := oidcAutherFromJWT(entry, []string{"RS256"})
	if err != nil {
		t.Fatalf("oidcAutherFromJWT() unexpected error: %v", err)
	}
	if auther == nil {
		t.Error("oidcAutherFromJWT() returned nil authenticator")
	}
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

	auther, issuerURLs, err := buildTokenAuther(opts)
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

	auther, issuerURLs, err := buildTokenAuther(opts)
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

func TestBuildTokenAuther_AuthConfig_InvalidFile(t *testing.T) {
	opts := &options.Options{
		OIDCAuthentication:   &options.OIDCAuthenticationOptions{SigningAlgs: []string{"RS256"}},
		AuthenticationConfig: &options.AuthenticationConfigOptions{ConfigFile: "/does/not/exist.yaml"},
	}

	_, _, err := buildTokenAuther(opts)
	if err == nil {
		t.Error("buildTokenAuther() expected error for missing config file, got nil")
	}
}
