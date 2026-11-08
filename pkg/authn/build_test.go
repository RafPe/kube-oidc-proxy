// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/client-go/util/cert"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
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

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestOIDCAuthenticatorFromJWT_Construction(t *testing.T) {
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

	authn, err := oidcAuthenticatorFromJWT(
		entry,
		authenticationcel.NewDefaultCompiler(),
		[]string{"RS256"},
		Config{},
	)
	if err != nil {
		t.Fatalf("oidcAuthenticatorFromJWT() unexpected error: %v", err)
	}
	if authn == nil {
		t.Error("oidcAuthenticatorFromJWT() returned nil authenticator")
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

func TestJWTAuthenticatorFromIssuer_RequiredClaims(t *testing.T) {
	t.Run("required claims are mapped into ClaimValidationRules", func(t *testing.T) {
		o := IssuerConfig{
			URL:           "https://vault.example.com",
			ClientID:      "my-client",
			UsernameClaim: "email",
			GroupsClaim:   "groups",
			SigningAlgs:   []string{"RS256"},
			RequiredClaims: map[string]string{
				"hd":   "example.com",
				"team": "platform",
			},
		}

		got := jwtAuthenticatorFromIssuer(o)

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
		o := IssuerConfig{
			URL:           "https://vault.example.com",
			ClientID:      "my-client",
			UsernameClaim: "email",
			GroupsClaim:   "groups",
			SigningAlgs:   []string{"RS256"},
		}

		got := jwtAuthenticatorFromIssuer(o)
		if len(got.ClaimValidationRules) != 0 {
			t.Errorf("ClaimValidationRules = %#v, want empty", got.ClaimValidationRules)
		}
	})
}

func TestBuildTokenAuthenticator_SingleIssuer(t *testing.T) {
	cfg := Config{Issuer: IssuerConfig{
		URL:           "https://vault.example.com/v1/identity/oidc",
		ClientID:      "my-client",
		UsernameClaim: "email",
		GroupsClaim:   "groups",
		SigningAlgs:   []string{"RS256"},
	}}

	authn, issuerURLs, err := Build(cfg, discardLogger(), discardLogger())
	if err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}
	if authn == nil {
		t.Error("Build() returned nil authenticator")
	}
	if want := []string{cfg.Issuer.URL}; len(issuerURLs) != len(want) || issuerURLs[0] != want[0] {
		t.Errorf("Build() issuerURLs = %v, want %v", issuerURLs, want)
	}
}

func TestBuildTokenAuthenticator_AuthConfig(t *testing.T) {
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

	authn, issuerURLs, err := Build(Config{ConfigFile: configPath}, discardLogger(), discardLogger())
	if err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}
	if authn == nil {
		t.Error("Build() returned nil authenticator")
	}
	want := []string{
		"https://vault.example.com/v1/identity/oidc",
		"https://issuer2.example.com/v1/identity/oidc",
	}
	if len(issuerURLs) != len(want) {
		t.Fatalf("Build() issuerURLs = %v, want %v", issuerURLs, want)
	}
	for i := range want {
		if issuerURLs[i] != want[i] {
			t.Errorf("Build() issuerURLs[%d] = %q, want %q", i, issuerURLs[i], want[i])
		}
	}
}

func TestBuildUnionAuthenticatorFromV1ConfigWithCEL(t *testing.T) {
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

	authn, issuerURLs, err := Build(Config{ConfigFile: path}, discardLogger(), discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authn == nil {
		t.Fatal("expected a token authenticator, got nil")
	}
	want := []string{"https://issuer1.example.com", "https://issuer2.example.com"}
	if !reflect.DeepEqual(issuerURLs, want) {
		t.Fatalf("expected issuer URLs %v, got %v", want, issuerURLs)
	}
}

func TestBuildTokenAuthenticator_AuthConfig_InvalidFile(t *testing.T) {
	_, _, err := Build(Config{ConfigFile: "/does/not/exist.yaml"}, discardLogger(), discardLogger())
	if err == nil {
		t.Error("Build() expected error for missing config file, got nil")
	}
}

// TestLogIssuersConfigured pins one record per configured issuer, each naming
// the issuer and the size of the set it belongs to. The previous behaviour was
// a single line with an interpolated slice, which no query can decompose.
func TestLogIssuersConfigured(t *testing.T) {
	root, cap := logtest.New(t, 0)

	logIssuersConfigured(logging.ForComponent(root, logging.ComponentOIDC),
		[]string{"idp.example.com", "github.example.com"})

	recs := cap.ByEvent(logging.EventOIDCIssuerConfigured)
	if len(recs) != 2 {
		t.Fatalf("got %d issuer records, want 2: %s", len(recs), cap.Raw())
	}

	var names []string
	for _, rec := range recs {
		names = append(names, rec.String("issuer_name"))
		if got, ok := rec.Int("issuer_count"); !ok || got != 2 {
			t.Errorf("issuer_count = %v, want 2", rec["issuer_count"])
		}
		if rec.String("msg") != "configured OIDC issuers" {
			t.Errorf("msg = %q, want %q", rec.String("msg"), "configured OIDC issuers")
		}
		if rec.String("component") != string(logging.ComponentOIDC) {
			t.Errorf("component = %q, want oidc", rec.String("component"))
		}
	}
	if want := []string{"idp.example.com", "github.example.com"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("issuer names = %v, want %v", names, want)
	}
}

// TestLogIssuersConfiguredNoIssuers pins the empty case: with no issuers
// configured there is nothing to announce, and an empty stream is not the same
// record with a zero count.
func TestLogIssuersConfiguredNoIssuers(t *testing.T) {
	root, cap := logtest.New(t, 0)

	logIssuersConfigured(logging.ForComponent(root, logging.ComponentOIDC), nil)

	if raw := cap.Raw(); raw != "" {
		t.Fatalf("records emitted with no issuers configured: %s", raw)
	}
}

// TestIssuerNamesDerivesFromURLs pins the never-log-a-full-
// issuer-URL constraint: the names handed to the record are hosts, and a value
// with no host degrades to the placeholder rather than to the URL itself.
func TestIssuerNamesDerivesFromURLs(t *testing.T) {
	got := issuerNames([]string{"https://idp.example.com/realms/corp", "not-a-url"})
	want := []string{"idp.example.com", "unknown"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("issuerNames = %v, want %v", got, want)
	}
}

// TestBuildTokenAuthenticatorRefusesIssuersSharingAHost pins the placement: the
// configuration is refused by Build itself, before it constructs
// any authenticator.
func TestBuildTokenAuthenticatorRefusesIssuersSharingAHost(t *testing.T) {
	config := filepath.Join(t.TempDir(), "auth.yaml")
	content := `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://idp.example.com/realms/a
      audiences:
        - a
    claimMappings:
      username:
        claim: email
        prefix: ""
  - issuer:
      url: https://idp.example.com/realms/b
      audiences:
        - b
    claimMappings:
      username:
        claim: email
        prefix: ""
`
	if err := os.WriteFile(config, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Build(Config{ConfigFile: config}, slog.New(slog.DiscardHandler), slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "share the name \"idp.example.com\"") {
		t.Fatalf("Build = %v, want the shared-host refusal", err)
	}
	// The name alone does not say which two entries have to be changed, so
	// both colliding URLs belong in the refusal.
	for _, want := range []string{"https://idp.example.com/realms/a", "https://idp.example.com/realms/b"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Build = %v, want it to name %q", err, want)
		}
	}
}

func TestDuplicateIssuerNameIsRefused(t *testing.T) {
	tests := map[string]struct {
		urls      []string
		wantDup   string
		wantFirst string
		wantOther string
	}{
		"distinct hosts": {urls: []string{"https://a.example.com", "https://b.example.com"}},
		"same host, other paths": {
			urls:      []string{"https://idp.example.com/realms/a", "https://idp.example.com/realms/b"},
			wantDup:   "idp.example.com",
			wantFirst: "https://idp.example.com/realms/a",
			wantOther: "https://idp.example.com/realms/b",
		},
		"single issuer": {urls: []string{"https://idp.example.com/realms/a"}},
		"the first URL under the name is the one reported": {
			urls:      []string{"https://a.example.com", "https://idp.example.com/realms/a", "https://idp.example.com/realms/b"},
			wantDup:   "idp.example.com",
			wantFirst: "https://idp.example.com/realms/a",
			wantOther: "https://idp.example.com/realms/b",
		},
		"two unparsable": {
			urls:      []string{"::", "::"},
			wantDup:   "unknown",
			wantFirst: "::",
			wantOther: "::",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dup, first, other, ok := duplicateIssuerName(tc.urls)
			if ok != (tc.wantDup != "") || dup != tc.wantDup || first != tc.wantFirst || other != tc.wantOther {
				t.Fatalf("duplicateIssuerName(%v) = %q, %q, %q, %v; want %q, %q, %q",
					tc.urls, dup, first, other, ok, tc.wantDup, tc.wantFirst, tc.wantOther)
			}
		})
	}
}
