// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/client-go/util/cert"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
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

// TestLogConfigLoaded pins the startup record that fixes what this pod is
// configured to do. It is the record an operator diffs between two pods, so
// every field it promises must be present and carry the value it was given.
func TestLogConfigLoaded(t *testing.T) {
	root, cap := logtest.New(t, 0)

	logConfigLoaded(logging.ForComponent(root, logging.ComponentStartup), configSummary{
		version:       "v1.5.0",
		configHash:    "0123456789abcdef",
		issuerCount:   2,
		readinessMode: "all",
	})

	rec := cap.Only(t, logging.EventProxyConfigLoaded)
	if rec.String("version") != "v1.5.0" {
		t.Errorf("version = %q", rec.String("version"))
	}
	if rec.String("config_hash") != "0123456789abcdef" {
		t.Errorf("config_hash = %q", rec.String("config_hash"))
	}
	if got, ok := rec.Int("issuer_count"); !ok || got != 2 {
		t.Errorf("issuer_count = %v", rec["issuer_count"])
	}
	if rec.String("readiness_mode") != "all" {
		t.Errorf("readiness_mode = %q", rec.String("readiness_mode"))
	}
	if rec.String("component") != string(logging.ComponentStartup) {
		t.Errorf("component = %q, want startup", rec.String("component"))
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

// TestIssuerNamesDerivesFromURLs pins the run.go side of the never-log-a-full-
// issuer-URL constraint: the names handed to the record are hosts, and a value
// with no host degrades to the placeholder rather than to the URL itself.
func TestIssuerNamesDerivesFromURLs(t *testing.T) {
	got := issuerNames([]string{"https://idp.example.com/realms/corp", "not-a-url"})
	want := []string{"idp.example.com", "unknown"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("issuerNames = %v, want %v", got, want)
	}
}

// TestStartupFailureAfterLoggerIsReportedAsARecord pins that an error raised
// once the root logger exists is emitted as proxy.startup.failed on the
// configured stream and returned as ErrReported, so main exits non-zero without
// appending a second, unstructured line to the container log.
func TestStartupFailureAfterLoggerIsReportedAsARecord(t *testing.T) {
	var out bytes.Buffer
	opts := options.New()
	cmd := buildRunCommand(opts, &out)
	opts.AddFlags(cmd)
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=kube-oidc-proxy",
		"--kubeconfig=" + filepath.Join(t.TempDir(), "missing-kubeconfig"),
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	err := cmd.Execute()
	if !errors.Is(err, ErrReported) {
		t.Fatalf("Execute() error = %v, want ErrReported", err)
	}

	var rec map[string]any
	found := false
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("non-JSON line on the log stream: %q", line)
		}
		if rec["event_type"] == string(logging.EventProxyStartupFailed) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no proxy.startup.failed record on the stream:\n%s", out.String())
	}
	if rec["level"] != "ERROR" || rec["component"] != string(logging.ComponentStartup) {
		t.Errorf("level/component = %v/%v, want ERROR/startup", rec["level"], rec["component"])
	}
	msg, _ := rec["error_message"].(string)
	if !strings.Contains(msg, "missing-kubeconfig") {
		t.Errorf("error_message = %q, want the underlying cause", msg)
	}
}
