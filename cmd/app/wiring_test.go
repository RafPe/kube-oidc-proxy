// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"reflect"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy"
)

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
	opts, _ := parsedCommand(t, args...)
	return opts
}

// parsedCommand is parsedOptions for a function that also reads which flags
// were set, which only the command that parsed the line records.
func parsedCommand(t *testing.T, args ...string) (*options.Options, *cobra.Command) {
	t.Helper()
	opts := options.New()
	cmd := &cobra.Command{Use: options.AppName}
	opts.AddFlags(cmd)
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}
	return opts, cmd
}

// TestBuildRESTConfigAppliesClientThrottling pins that --kube-client-qps and
// --kube-client-burst reach the client configuration, and that leaving them
// unset keeps client-go's own defaults rather than writing zero over them.
func TestBuildRESTConfigAppliesClientThrottling(t *testing.T) {
	// --server selects the flag-built configuration over the in-cluster one,
	// which a test process cannot load.
	opts, cmd := parsedCommand(t,
		"--server=https://api.example.test:6443",
		"--kube-client-qps=7.5",
		"--kube-client-burst=42",
	)
	cfg, err := buildRESTConfig(opts, cmd)
	if err != nil {
		t.Fatalf("buildRESTConfig() error = %v", err)
	}
	if cfg.QPS != 7.5 || cfg.Burst != 42 {
		t.Errorf("QPS/Burst = %v/%d, want 7.5/42", cfg.QPS, cfg.Burst)
	}

	opts, cmd = parsedCommand(t, "--server=https://api.example.test:6443")
	cfg, err = buildRESTConfig(opts, cmd)
	if err != nil {
		t.Fatalf("buildRESTConfig() without throttling flags error = %v", err)
	}
	if cfg.QPS != 0 || cfg.Burst != 0 {
		t.Errorf("QPS/Burst = %v/%d without the flags, want 0/0 so client-go applies its defaults", cfg.QPS, cfg.Burst)
	}
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

// TestAuthenticatorConfigPassesPrefixesThroughVerbatim pins the prefix
// semantics this proxy has always had, which differ from kube-apiserver's
// flags of the same name: no issuer-URL default when the prefix is empty, and
// no '-' opt-out. Translating either would rename every user on an existing
// deployment and break its RBAC bindings.
func TestAuthenticatorConfigPassesPrefixesThroughVerbatim(t *testing.T) {
	for _, prefix := range []string{"", "-", "oidc:"} {
		opts := parsedOptions(t,
			"--oidc-issuer-url=https://issuer.example.com",
			"--oidc-username-claim=email",
			"--oidc-username-prefix="+prefix,
			"--oidc-groups-prefix="+prefix,
		)
		got := authenticatorConfig(opts).Issuer
		if got.UsernamePrefix != prefix || got.GroupsPrefix != prefix {
			t.Errorf("prefix %q mapped to username %q, groups %q; want it unchanged",
				prefix, got.UsernamePrefix, got.GroupsPrefix)
		}
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

	want := proxy.Config{
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

	if r := buildTokenReviewer(parsedOptions(t), client, nil, discard); r != nil {
		t.Fatalf("passthrough disabled: reviewer %T, want none", r)
	}
	if r := buildTokenReviewer(parsedOptions(t, "--token-passthrough"), client, nil, discard); r == nil {
		t.Fatal("passthrough enabled: no reviewer, want one")
	}
}

// TestConfigHash pins the three properties the startup record relies on: the
// digest is stable, it changes with any non-secret value, and it never
// depends on a secret, so two pods differing only in a credential compare
// equal and the digest cannot be used to test a guessed credential. It runs
// against the command's real flag set, so every secretFlags entry must name a
// flag the proxy actually registers.
func TestConfigHash(t *testing.T) {
	hash := func(args ...string) string {
		t.Helper()
		opts := options.New()
		cmd := &cobra.Command{Use: "test"}
		opts.AddFlags(cmd)
		if err := cmd.ParseFlags(args); err != nil {
			t.Fatal(err)
		}
		return configHash(cmd.Flags())
	}

	opts := options.New()
	cmd := &cobra.Command{Use: "test"}
	opts.AddFlags(cmd)
	for name := range secretFlags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("secretFlags names --%s, which the command does not register", name)
		}
	}

	base := hash("--oidc-issuer-url=https://a")
	if len(base) != configHashLength {
		t.Fatalf("hash %q has length %d, want %d", base, len(base), configHashLength)
	}
	if again := hash("--oidc-issuer-url=https://a"); again != base {
		t.Fatalf("hash not stable: %q then %q", base, again)
	}
	if other := hash("--oidc-issuer-url=https://b"); other == base {
		t.Fatal("hash unchanged by a different issuer")
	}
	if secret := hash("--oidc-issuer-url=https://a", "--token=t0k3n"); secret != base {
		t.Fatalf("hash depends on the --token value: %q vs %q", secret, base)
	}
}

// TestConfigHashIsStableForMapFlags pins the digest across repeated
// computation when a map-valued flag holds several keys. Go randomises map
// iteration, so a flag whose String() walked its map unsorted fingerprinted
// identical pods differently.
func TestConfigHashIsStableForMapFlags(t *testing.T) {
	opts := options.New()
	cmd := &cobra.Command{Use: "test"}
	opts.AddFlags(cmd)
	if err := cmd.ParseFlags([]string{
		"--extra-user-headers=team=a,region=eu,tier=gold,zone=b,owner=ops,team=c",
	}); err != nil {
		t.Fatal(err)
	}

	want := configHash(cmd.Flags())
	for range 50 {
		if got := configHash(cmd.Flags()); got != want {
			t.Fatalf("config hash changed between computations: %q then %q", want, got)
		}
	}
}
