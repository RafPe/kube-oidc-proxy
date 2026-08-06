// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

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
		"non-oidc flag changed": {
			changedFlags: []string{"secure-port"},
			want:         false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := New()
			cmd := &cobra.Command{}
			o.AddFlags(cmd)

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
	tests := map[string]struct {
		configFile    string
		changedFlags  []string
		wantErrSubstr string
	}{
		"both authentication-config and oidc-issuer-url is an error": {
			configFile:    "/some/path",
			changedFlags:  []string{"oidc-issuer-url"},
			wantErrSubstr: "mutually exclusive",
		},
		"both authentication-config and oidc-ca-file is an error": {
			configFile:    "/some/path",
			changedFlags:  []string{"oidc-ca-file"},
			wantErrSubstr: "mutually exclusive",
		},
		"authentication-config without oidc flags is not a mutual exclusivity error": {
			configFile: "/some/path",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := New()
			cmd := &cobra.Command{}
			o.AddFlags(cmd)

			o.AuthenticationConfig.ConfigFile = tc.configFile
			for _, flagName := range tc.changedFlags {
				if err := cmd.Flags().Set(flagName, "https://issuer.example.com"); err != nil {
					t.Fatalf("setting flag %q: %v", flagName, err)
				}
			}

			err := o.Validate(cmd)
			if tc.wantErrSubstr == "" {
				if err != nil && strings.Contains(err.Error(), "mutually exclusive") {
					t.Errorf("Validate() unexpected mutual exclusivity error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tc.wantErrSubstr)
				}
			}
		})
	}
}
