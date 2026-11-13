// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"

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

// documentIssuer is a configuration-document issuer as LoadConfiguration
// returns it, with an inline CA when ca is not empty.
func documentIssuer(ca string) issuer {
	emptyPrefix := ""
	return issuer{
		jwt: apiserverapi.JWTAuthenticator{
			Issuer: apiserverapi.Issuer{
				URL:                  "https://vault.example.com/v1/identity/oidc",
				Audiences:            []string{"my-client"},
				CertificateAuthority: ca,
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
		},
		signingAlgs: []string{"RS256"},
	}
}

func TestNewIssuerAuthenticator_Construction(t *testing.T) {
	tests := map[string]string{
		"system roots":                "",
		"inline certificateAuthority": string(selfSignedCA(t)),
	}
	for name, ca := range tests {
		t.Run(name, func(t *testing.T) {
			authn, err := newIssuerAuthenticator(documentIssuer(ca), authenticationcel.NewDefaultCompiler(), Config{}, discardLogger())
			if err != nil {
				t.Fatalf("newIssuerAuthenticator() unexpected error: %v", err)
			}
			if authn == nil {
				t.Error("newIssuerAuthenticator() returned nil authenticator")
			}
		})
	}
}

// TestBuildPanicsOnNilLoggers pins that a missing logger is a wiring mistake
// that fails at construction, naming the package and the logger.
func TestBuildPanicsOnNilLoggers(t *testing.T) {
	cfg := Config{Issuer: IssuerConfig{URL: "https://vault.example.com", ClientID: "my-client", UsernameClaim: "sub"}}
	tests := map[string]struct {
		oidcLogger, startupLogger *slog.Logger
		want                      string
	}{
		"nil oidc logger":    {nil, discardLogger(), "authn: nil oidc logger"},
		"nil startup logger": {discardLogger(), nil, "authn: nil startup logger"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if got := recover(); got != tc.want {
					t.Fatalf("Build panic = %v, want %q", got, tc.want)
				}
			}()
			_, _, _ = Build(cfg, tc.oidcLogger, tc.startupLogger)
		})
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
// the issuer and the size of the set it belongs to, so a query lists the
// issuers without decomposing an interpolated slice.
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
	// The name alone does not say which two entries have to be changed, so
	// the refusal names both by position; the full URLs are never in it.
	want := `issuers jwt[0] and jwt[1] share the name "idp.example.com"; issuers must differ by host`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Build = %v, want the shared-host refusal %q", err, want)
	}
	if strings.Contains(err.Error(), "/realms/") {
		t.Fatalf("Build = %v, want no full issuer URL in the refusal", err)
	}
}

func TestDuplicateIssuerNameIsRefused(t *testing.T) {
	tests := map[string]struct {
		urls      []string
		wantDup   string
		wantFirst int
		wantOther int
	}{
		"distinct hosts": {urls: []string{"https://a.example.com", "https://b.example.com"}},
		"same host, other paths": {
			urls:      []string{"https://idp.example.com/realms/a", "https://idp.example.com/realms/b"},
			wantDup:   "idp.example.com",
			wantFirst: 0,
			wantOther: 1,
		},
		"single issuer": {urls: []string{"https://idp.example.com/realms/a"}},
		"the first entry under the name is the one reported": {
			urls:      []string{"https://a.example.com", "https://idp.example.com/realms/a", "https://idp.example.com/realms/b"},
			wantDup:   "idp.example.com",
			wantFirst: 1,
			wantOther: 2,
		},
		"two unparsable": {
			urls:      []string{"::", "::"},
			wantDup:   "unknown",
			wantFirst: 0,
			wantOther: 1,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dup, first, other, ok := duplicateIssuerName(tc.urls)
			if ok != (tc.wantDup != "") || dup != tc.wantDup || first != tc.wantFirst || other != tc.wantOther {
				t.Fatalf("duplicateIssuerName(%v) = %q, %d, %d, %v; want %q, %d, %d",
					tc.urls, dup, first, other, ok, tc.wantDup, tc.wantFirst, tc.wantOther)
			}
		})
	}
}

// TestBuildErrorNamesIssuerByHost pins that a failure to build one issuer's
// authenticator names the issuer by IssuerName, never by its full URL.
func TestBuildErrorNamesIssuerByHost(t *testing.T) {
	cfg := Config{
		Issuer:            IssuerConfig{URL: "https://idp.example.com/realms/secret", ClientID: "my-client", UsernameClaim: "sub"},
		TLSClientCertFile: filepath.Join(t.TempDir(), "missing.crt"),
		TLSClientKeyFile:  filepath.Join(t.TempDir(), "missing.key"),
	}
	_, _, err := Build(cfg, discardLogger(), discardLogger())
	if err == nil || !strings.Contains(err.Error(), `building authenticator for issuer "idp.example.com"`) {
		t.Fatalf("Build = %v, want the failure attributed to idp.example.com", err)
	}
	if strings.Contains(err.Error(), "/realms/secret") {
		t.Fatalf("Build = %v, want no full issuer URL", err)
	}
}
