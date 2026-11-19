// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

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

// TestBuildPanicsOnNilLogger pins that a missing logger is a wiring mistake
// that fails at construction, naming the package and the logger.
func TestBuildPanicsOnNilLogger(t *testing.T) {
	cfg := Config{Issuer: IssuerConfig{URL: "https://vault.example.com", ClientID: "my-client", UsernameClaim: "sub"}}
	defer func() {
		if got, want := recover(), "authn: nil logger"; got != want {
			t.Fatalf("Build panic = %v, want %q", got, want)
		}
	}()
	_, _, _ = Build(cfg, nil)
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

	authn, issuers, err := Build(cfg, discardLogger())
	if err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}
	if authn == nil {
		t.Error("Build() returned nil authenticator")
	}
	want := []Issuer{{Name: "vault.example.com", URL: cfg.Issuer.URL, Audiences: []string{"my-client"}}}
	if !reflect.DeepEqual(issuers, want) {
		t.Errorf("Build() issuers = %+v, want %+v", issuers, want)
	}
}

// TestBuildDerivesTheOIDCComponent pins that Build reports the issuers it
// configured under the oidc component it derives from the root logger.
func TestBuildDerivesTheOIDCComponent(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)
	cfg := Config{Issuer: IssuerConfig{URL: "https://vault.example.com", ClientID: "my-client", UsernameClaim: "sub"}}

	if _, _, err := Build(cfg, root); err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}

	rec := cap.Only(t, logging.EventOIDCIssuerConfigured)
	if got := rec.String("component"); got != string(logging.ComponentOIDC) {
		t.Errorf("component = %q, want %q", got, logging.ComponentOIDC)
	}
}

func TestBuildTokenAuthenticator_AuthConfig(t *testing.T) {
	configPath := writeDoc(t, marshalDoc(t, upstreamDoc(
		testJWT("https://vault.example.com/v1/identity/oidc", "", "my-client"),
		testJWT("https://issuer2.example.com/v1/identity/oidc", "", "kubernetes"))))

	authn, issuers, err := Build(Config{ConfigFile: configPath}, discardLogger())
	if err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}
	if authn == nil {
		t.Error("Build() returned nil authenticator")
	}
	want := []Issuer{
		{Name: "vault.example.com", URL: "https://vault.example.com/v1/identity/oidc", Audiences: []string{"my-client"}},
		{Name: "issuer2.example.com", URL: "https://issuer2.example.com/v1/identity/oidc", Audiences: []string{"kubernetes"}},
	}
	if !reflect.DeepEqual(issuers, want) {
		t.Fatalf("Build() issuers = %+v, want %+v", issuers, want)
	}
}

func TestBuildUnionAuthenticatorFromV1ConfigWithCEL(t *testing.T) {
	path := writeDoc(t, marshalDoc(t, upstreamDoc(
		celJWT(),
		testJWT("https://issuer2.example.com", "two:", "aud-two"))))

	authn, issuers, err := Build(Config{ConfigFile: path}, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authn == nil {
		t.Fatal("expected a token authenticator, got nil")
	}
	want := []Issuer{
		{Name: "issuer1.example.com", URL: "https://issuer1.example.com", Audiences: []string{"aud-one"}},
		{Name: "issuer2.example.com", URL: "https://issuer2.example.com", Audiences: []string{"aud-two"}},
	}
	if !reflect.DeepEqual(issuers, want) {
		t.Fatalf("Build() issuers = %+v, want %+v", issuers, want)
	}
}

func TestBuildTokenAuthenticator_AuthConfig_InvalidFile(t *testing.T) {
	_, _, err := Build(Config{ConfigFile: "/does/not/exist.yaml"}, discardLogger())
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
	config := writeDoc(t, marshalDoc(t, upstreamDoc(
		testJWT("https://idp.example.com/realms/a", "", "a"),
		testJWT("https://idp.example.com/realms/b", "", "b"))))
	_, _, err := Build(Config{ConfigFile: config}, discardLogger())
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
	_, _, err := Build(cfg, discardLogger())
	if err == nil || !strings.Contains(err.Error(), `building authenticator for issuer "idp.example.com"`) {
		t.Fatalf("Build = %v, want the failure attributed to idp.example.com", err)
	}
	if strings.Contains(err.Error(), "/realms/secret") {
		t.Fatalf("Build = %v, want no full issuer URL", err)
	}
}

// TestBuildProxyKindUsesConfiguredNames pins that issuers of the proxy kind
// carry their configured names, also when two issuers share a host.
func TestBuildProxyKindUsesConfiguredNames(t *testing.T) {
	_, issuers, err := Build(Config{ConfigFile: writeDoc(t, marshalDoc(t, gkeProxyDoc()))}, discardLogger())
	if err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}
	want := []Issuer{
		{
			Name:      "gke-vendor",
			URL:       gkeVendorURL,
			Audiences: []string{"aud-vendor"},
		},
		{
			Name:      "gke-internal",
			URL:       gkeInternalURL,
			Audiences: []string{"aud-internal"},
		},
	}
	if !reflect.DeepEqual(issuers, want) {
		t.Fatalf("Build() issuers = %+v, want %+v", issuers, want)
	}
}

// TestBuildRefusesProxyKindIssuersSharingAURL pins that Build refuses two
// issuers with one issuer URL until the proxy can route a token between them.
func TestBuildRefusesProxyKindIssuersSharingAURL(t *testing.T) {
	config := writeDoc(t, marshalDoc(t, proxyDoc(
		proxyIssuer("gha-int", ghaURL, "aud-int"),
		proxyIssuer("gha-vendor", ghaURL, "aud-vendor"))))

	_, _, err := Build(Config{ConfigFile: config}, discardLogger())
	if err == nil {
		t.Fatal("Build() error = nil, want a refusal")
	}
	for _, want := range []string{"issuers[0]", "issuers[1]", "same issuer URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Build() error = %v, want it to contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "token.actions.githubusercontent.com") {
		t.Fatalf("Build() error = %v, must not contain the issuer URL", err)
	}
}
