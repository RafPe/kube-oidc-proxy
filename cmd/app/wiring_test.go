// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy"
)

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

// parsedOptions registers every flag the command does and parses args, so a
// mapping test reads the options exactly as RunE would.
func parsedOptions(t *testing.T, args ...string) *options.Options {
	t.Helper()
	opts := options.New()
	cmd := &cobra.Command{Use: options.AppName}
	opts.AddFlags(cmd)
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}
	return opts
}

// TestAuthenticatorConfigMapsEveryOIDCFlag pins the flag-to-config mapping
// for the authenticator: a flag that parses but never reaches authn.Config is
// silently ignored at runtime, and only the kind e2e suite would notice.
func TestAuthenticatorConfigMapsEveryOIDCFlag(t *testing.T) {
	opts := parsedOptions(t,
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=client",
		"--oidc-ca-file=/ca.pem",
		"--oidc-username-claim=email",
		"--oidc-username-prefix=oidc:",
		"--oidc-groups-claim=groups",
		"--oidc-groups-prefix=oidc:",
		"--oidc-signing-algs=RS256,ES256",
		"--oidc-required-claim=hd=example.com",
		"--oidc-tls-client-cert-file=/client.crt",
		"--oidc-tls-client-key-file=/client.key",
		"--authentication-config=/authn.yaml",
	)

	want := authn.Config{
		ConfigFile: "/authn.yaml",
		Issuer: authn.IssuerConfig{
			URL:            "https://issuer.example.com",
			ClientID:       "client",
			CAFile:         "/ca.pem",
			UsernameClaim:  "email",
			UsernamePrefix: "oidc:",
			GroupsClaim:    "groups",
			GroupsPrefix:   "oidc:",
			SigningAlgs:    []string{"RS256", "ES256"},
			RequiredClaims: map[string]string{"hd": "example.com"},
		},
		TLSClientCertFile: "/client.crt",
		TLSClientKeyFile:  "/client.key",
	}
	if got := authenticatorConfig(opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("authenticatorConfig:\n got %+v\nwant %+v", got, want)
	}
}

// TestProxyConfigMapsEveryProxyFlag pins the flag-to-config mapping for the
// proxy itself.
func TestProxyConfigMapsEveryProxyFlag(t *testing.T) {
	opts := parsedOptions(t,
		"--token-passthrough",
		"--disable-impersonation",
		"--flush-interval=2s",
		"--bind-address=10.0.0.1",
		"--extra-user-headers=team=a,team=b",
		"--extra-user-header-client-ip",
		"--trusted-proxies=10.0.0.0/8",
		"--allow-reserved-groups=system:masters",
	)

	want := &proxy.Config{
		TokenPassthrough:                true,
		DisableImpersonation:            true,
		FlushInterval:                   2 * time.Second,
		ExtraUserHeaders:                map[string][]string{"team": {"a", "b"}},
		ExtraUserHeadersClientIPEnabled: true,
		TrustedProxies:                  []string{"10.0.0.0/8"},
		AllowedReservedGroups:           []string{"system:masters"},
	}
	if got := proxyConfig(opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("proxyConfig:\n got %+v\nwant %+v", got, want)
	}
}

// TestBuildTokenReviewerOnlyWithPassthrough pins that the reviewer exists
// exactly when passthrough is enabled: a nil reviewer is how the proxy knows
// to skip the TokenReview fallback.
func TestBuildTokenReviewerOnlyWithPassthrough(t *testing.T) {
	client := fake.NewSimpleClientset()
	discard := slog.New(slog.DiscardHandler)

	if r := buildTokenReviewer(parsedOptions(t), client, nil, discard); r != nil {
		t.Fatalf("reviewer built with passthrough disabled: %T", r)
	}
	if r := buildTokenReviewer(parsedOptions(t, "--token-passthrough"), client, nil, discard); r == nil {
		t.Fatal("no reviewer built with passthrough enabled")
	}
}

// TestIssuerProbesCoverEveryIssuer pins one readiness entry per issuer, in
// configuration order.
func TestIssuerProbesCoverEveryIssuer(t *testing.T) {
	urls := []string{"https://a.example.com", "https://b.example.com"}
	probes, err := issuerProbes(urls)
	if err != nil {
		t.Fatalf("issuerProbes: %v", err)
	}
	if len(probes) != len(urls) {
		t.Fatalf("got %d probes, want %d", len(probes), len(urls))
	}
	for i, p := range probes {
		if p.IssuerURL != urls[i] || p.FakeJWT == "" {
			t.Fatalf("probe %d = %+v, want issuer %q with a token", i, p, urls[i])
		}
	}
}

// TestConfigHash pins the three properties the startup record relies on: the
// digest is stable, it changes with any non-secret value, and it never
// depends on a secret, so two pods differing only in a credential compare
// equal and the digest cannot be used to test a guessed credential.
func TestConfigHash(t *testing.T) {
	hash := func(args ...string) string {
		t.Helper()
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		fs.String("issuer", "", "")
		fs.String("token", "", "")
		fs.String("password", "", "")
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return configHash(fs)
	}

	base := hash("--issuer=https://a")
	if len(base) != configHashLength {
		t.Fatalf("hash %q has length %d, want %d", base, len(base), configHashLength)
	}
	if again := hash("--issuer=https://a"); again != base {
		t.Fatalf("hash not stable: %q then %q", base, again)
	}
	if other := hash("--issuer=https://b"); other == base {
		t.Fatal("hash unchanged by a different issuer")
	}
	if secret := hash("--issuer=https://a", "--token=t0k3n", "--password=pw"); secret != base {
		t.Fatalf("hash depends on a secret flag: %q vs %q", secret, base)
	}
}
