// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	certutil "k8s.io/client-go/util/cert"
)

// newTestOptions returns options bound to a command, as New and AddFlags
// leave them. With no flag set they pass Validate, so a table case changes
// only what it is about and a success case can assert a nil error.
func newTestOptions(t *testing.T) (*Options, *cobra.Command) {
	t.Helper()
	o := New()
	cmd := &cobra.Command{Use: "test"}
	o.AddFlags(cmd)
	if err := o.Validate(cmd); err != nil {
		t.Fatalf("Validate() on the defaults = %v, want nil", err)
	}
	return o, cmd
}

// checkValidateError fails t unless err is nil when want is empty, or
// carries every message in want otherwise.
func checkValidateError(t *testing.T, err error, want ...string) {
	t.Helper()
	if len(want) == 0 {
		if err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("Validate() = nil, want errors containing %q", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("Validate() = %v, want an error containing %q", err, w)
		}
	}
}

// writeFile writes data to a new file under t's temporary directory and
// returns its path.
func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOidcFlagsChanged(t *testing.T) {
	tests := map[string]struct {
		changedFlags []string
		want         bool
	}{
		"no flags changed": {
			want: false,
		},
		"oidc-issuer-url changed": {
			changedFlags: []string{"oidc-issuer-url"},
			want:         true,
		},
		"oidc-signing-algs changed": {
			changedFlags: []string{"oidc-signing-algs"},
			want:         true,
		},
		"OIDC TLS client certificate is shared with authentication-config": {
			changedFlags: []string{"oidc-tls-client-cert-file"},
			want:         false,
		},
		"non-oidc flag changed": {
			changedFlags: []string{"secure-port"},
			want:         false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o, cmd := newTestOptions(t)

			// Guard against a silently-empty derivation: if FlagSet("OIDC")
			// returned a fresh empty set, oidcFlagsChanged would always report
			// false and the mutual-exclusion guard would become a no-op.
			visited := 0
			o.nfs.FlagSet("OIDC").VisitAll(func(*pflag.Flag) { visited++ })
			if visited == 0 {
				t.Fatal("OIDC flag set is empty; oidcFlagsChanged would never detect a changed flag")
			}

			for _, flagName := range tc.changedFlags {
				// "8443" is a valid value for every flag exercised here,
				// including the integer --secure-port.
				if err := cmd.Flags().Set(flagName, "8443"); err != nil {
					t.Fatalf("setting flag %q: %v", flagName, err)
				}
			}

			if got := o.oidcFlagsChanged(cmd); got != tc.want {
				t.Errorf("oidcFlagsChanged() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidate_MutualExclusivity(t *testing.T) {
	const wantErr = "--authentication-config and the issuer-specific --oidc-* flags are mutually exclusive"

	certPEM, keyPEM, err := certutil.GenerateSelfSignedCertKey("client", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	certFile := writeFile(t, "client.crt", certPEM)
	keyFile := writeFile(t, "client.key", keyPEM)

	tests := map[string]struct {
		args    []string
		wantErr string
	}{
		"both authentication-config and oidc-issuer-url is an error": {
			args:    []string{"--oidc-issuer-url=https://issuer.example.com"},
			wantErr: wantErr,
		},
		"both authentication-config and oidc-ca-file is an error": {
			args:    []string{"--oidc-ca-file=" + certFile},
			wantErr: wantErr,
		},
		"authentication-config without oidc flags is valid": {},
		"authentication-config accepts shared OIDC TLS credentials": {
			args: []string{"--oidc-tls-client-cert-file=" + certFile, "--oidc-tls-client-key-file=" + keyFile},
		},
	}

	configFile := writeFile(t, "authentication.yaml", nil)
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o, cmd := newTestOptions(t)
			if err := cmd.ParseFlags(append([]string{"--authentication-config=" + configFile}, tc.args...)); err != nil {
				t.Fatal(err)
			}

			if tc.wantErr == "" {
				checkValidateError(t, o.Validate(cmd))
			} else {
				checkValidateError(t, o.Validate(cmd), tc.wantErr)
			}
		})
	}
}

// TestValidate_ReservedIdentityPrefixes pins that a single-issuer prefix that
// would mint reserved identities for every user is refused with the other
// flag errors, each prefix reported on its own, and that the --oidc-*
// prefixes are not checked with --authentication-config, which ignores them.
func TestValidate_ReservedIdentityPrefixes(t *testing.T) {
	const (
		usernameErr = `--oidc-username-prefix "system:" would prefix every authenticated identity`
		groupsErr   = `--oidc-groups-prefix "system:serviceaccount:" would prefix every authenticated identity`
	)

	tests := map[string]struct {
		usernamePrefix string
		groupsPrefix   string
		configFile     bool
		wantErrs       []string
	}{
		"no prefixes": {},
		"ordinary prefixes": {
			usernamePrefix: "oidc:",
			groupsPrefix:   "oidc:",
		},
		"reserved username prefix": {
			usernamePrefix: "system:",
			wantErrs:       []string{usernameErr},
		},
		"reserved groups prefix": {
			groupsPrefix: "system:serviceaccount:",
			wantErrs:     []string{groupsErr},
		},
		"both reserved prefixes are reported together": {
			usernamePrefix: "system:",
			groupsPrefix:   "system:serviceaccount:",
			wantErrs:       []string{usernameErr, groupsErr},
		},
		"reserved prefix ignored in multi-issuer mode": {
			usernamePrefix: "system:",
			configFile:     true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o, cmd := newTestOptions(t)
			// Set on the options rather than the flags: in multi-issuer mode
			// changing an --oidc-* flag is itself an error.
			o.OIDCAuthentication.UsernamePrefix = tc.usernamePrefix
			o.OIDCAuthentication.GroupsPrefix = tc.groupsPrefix
			if tc.configFile {
				o.AuthenticationConfig.ConfigFile = writeFile(t, "authentication.yaml", nil)
			}

			checkValidateError(t, o.Validate(cmd), tc.wantErrs...)
		})
	}
}

// TestValidate_ExtraHeadersRequireImpersonation pins that each extra user
// header flag is refused, by name, with --disable-impersonation: the headers
// belong to the impersonated request, which is never sent.
func TestValidate_ExtraHeadersRequireImpersonation(t *testing.T) {
	tests := map[string]struct {
		args     []string
		wantErrs []string
	}{
		"extra headers with impersonation are valid": {
			args: []string{"--extra-user-header-client-ip", "--extra-user-headers=team=a"},
		},
		"disabled impersonation alone is valid": {
			args: []string{"--disable-impersonation"},
		},
		"client IP header with disabled impersonation is rejected": {
			args:     []string{"--disable-impersonation", "--extra-user-header-client-ip"},
			wantErrs: []string{"--extra-user-header-client-ip cannot be used with --disable-impersonation"},
		},
		"both header flags with disabled impersonation are each rejected": {
			args: []string{"--disable-impersonation", "--extra-user-header-client-ip", "--extra-user-headers=team=a"},
			wantErrs: []string{
				"--extra-user-header-client-ip cannot be used with --disable-impersonation",
				"--extra-user-headers cannot be used with --disable-impersonation",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o, cmd := newTestOptions(t)
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			checkValidateError(t, o.Validate(cmd), tc.wantErrs...)
		})
	}
}

// TestValidate_ProxyListFlags pins that --trusted-proxies and
// --allow-reserved-groups are checked with the other flags, by the proxy's
// own rules, and reported under their flag names.
func TestValidate_ProxyListFlags(t *testing.T) {
	tests := map[string]struct {
		args    []string
		wantErr string
	}{
		"valid trusted proxies": {
			args: []string{"--trusted-proxies=10.0.0.0/8,2001:db8::/32"},
		},
		"valid reserved groups": {
			args: []string{"--allow-reserved-groups=system:monitoring"},
		},
		"malformed trusted proxy CIDR is rejected": {
			args:    []string{"--trusted-proxies=10.0.0.0/8,bogus"},
			wantErr: `--trusted-proxies: invalid trusted-proxy CIDR "bogus"`,
		},
		"unreserved allowed group is rejected": {
			args:    []string{"--allow-reserved-groups=admins"},
			wantErr: `--allow-reserved-groups: allowed reserved group "admins" does not carry the reserved "system:" prefix`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o, cmd := newTestOptions(t)
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			if tc.wantErr == "" {
				checkValidateError(t, o.Validate(cmd))
			} else {
				checkValidateError(t, o.Validate(cmd), tc.wantErr)
			}
		})
	}
}
