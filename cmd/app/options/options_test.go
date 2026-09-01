// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
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
		"authentication-config accepts shared OIDC TLS credentials": {
			configFile:   "/some/path",
			changedFlags: []string{"oidc-tls-client-cert-file"},
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

func TestValidate_SubjectAccessReviewTimeout(t *testing.T) {
	const wantErrSubstr = "--subject-access-review-timeout must be greater than 0"

	tests := map[string]struct {
		timeout time.Duration
		wantErr bool
	}{
		"default is valid":         {timeout: subjectaccessreview.DefaultTimeout, wantErr: false},
		"custom positive is valid": {timeout: 2 * time.Second, wantErr: false},
		"zero is rejected":         {timeout: 0, wantErr: true},
		"negative is rejected":     {timeout: -1 * time.Second, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := New()
			cmd := &cobra.Command{}
			o.AddFlags(cmd)

			o.App.SubjectAccessReviewTimeout = tc.timeout

			err := o.Validate(cmd)
			gotErr := err != nil && strings.Contains(err.Error(), wantErrSubstr)
			if gotErr != tc.wantErr {
				t.Errorf("Validate() timeout error present = %v (err=%v), want %v", gotErr, err, tc.wantErr)
			}
		})
	}
}

func TestValidate_SubjectAccessReviewCacheTTLs(t *testing.T) {
	flags := map[string]struct {
		wantErrSubstr string
		set           func(o *Options, ttl time.Duration)
	}{
		"subject-access-review-allow-cache-ttl": {
			wantErrSubstr: "--subject-access-review-allow-cache-ttl must not be negative",
			set:           func(o *Options, ttl time.Duration) { o.App.SubjectAccessReviewAllowCacheTTL = ttl },
		},
		"subject-access-review-deny-cache-ttl": {
			wantErrSubstr: "--subject-access-review-deny-cache-ttl must not be negative",
			set:           func(o *Options, ttl time.Duration) { o.App.SubjectAccessReviewDenyCacheTTL = ttl },
		},
	}

	tests := map[string]struct {
		ttl     time.Duration
		wantErr bool
	}{
		"default is valid":           {ttl: subjectaccessreview.DefaultAllowCacheTTL, wantErr: false},
		"custom positive is valid":   {ttl: time.Minute, wantErr: false},
		"zero (disabling) is valid":  {ttl: 0, wantErr: false},
		"negative is rejected":       {ttl: -1 * time.Second, wantErr: true},
		"large negative is rejected": {ttl: -time.Hour, wantErr: true},
	}

	for flagName, flag := range flags {
		t.Run(flagName, func(t *testing.T) {
			for name, tc := range tests {
				t.Run(name, func(t *testing.T) {
					o := New()
					cmd := &cobra.Command{}
					o.AddFlags(cmd)

					flag.set(o, tc.ttl)

					err := o.Validate(cmd)
					gotErr := err != nil && strings.Contains(err.Error(), flag.wantErrSubstr)
					if gotErr != tc.wantErr {
						t.Errorf("Validate() TTL error present = %v (err=%v), want %v", gotErr, err, tc.wantErr)
					}
				})
			}
		})
	}
}
