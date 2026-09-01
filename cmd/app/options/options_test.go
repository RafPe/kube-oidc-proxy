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

// TestValidate_TokenPassthroughCacheTTLs pins that the cache TTL flags reject
// negative values regardless of whether --token-passthrough is enabled, so a
// broken value cannot lie dormant until the feature is switched on. Zero stays
// valid: it disables that class of caching.
func TestValidate_TokenPassthroughCacheTTLs(t *testing.T) {
	tests := map[string]struct {
		successTTL         time.Duration
		failureTTL         time.Duration
		passthroughEnabled bool
		wantErrSubstr      string
	}{
		"defaults are valid": {
			successTTL: 10 * time.Second,
			failureTTL: 10 * time.Second,
		},
		"zero TTLs are valid (caching disabled)": {
			successTTL:         0,
			failureTTL:         0,
			passthroughEnabled: true,
		},
		"negative success TTL is rejected": {
			successTTL:         -1 * time.Second,
			failureTTL:         10 * time.Second,
			passthroughEnabled: true,
			wantErrSubstr:      "--token-passthrough-cache-success-ttl must not be negative",
		},
		"negative failure TTL is rejected": {
			successTTL:         10 * time.Second,
			failureTTL:         -1 * time.Second,
			passthroughEnabled: true,
			wantErrSubstr:      "--token-passthrough-cache-failure-ttl must not be negative",
		},
		"negative success TTL is rejected even with passthrough disabled": {
			successTTL:    -1 * time.Second,
			failureTTL:    10 * time.Second,
			wantErrSubstr: "--token-passthrough-cache-success-ttl must not be negative",
		},
		"negative failure TTL is rejected even with passthrough disabled": {
			successTTL:    10 * time.Second,
			failureTTL:    -1 * time.Second,
			wantErrSubstr: "--token-passthrough-cache-failure-ttl must not be negative",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := New()
			cmd := &cobra.Command{}
			o.AddFlags(cmd)

			o.App.TokenPassthrough.Enabled = tc.passthroughEnabled
			o.App.TokenPassthrough.CacheSuccessTTL = tc.successTTL
			o.App.TokenPassthrough.CacheFailureTTL = tc.failureTTL

			err := o.Validate(cmd)
			if tc.wantErrSubstr == "" {
				if err != nil && strings.Contains(err.Error(), "cache") {
					t.Errorf("Validate() unexpected cache TTL error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Errorf("Validate() error = %v, want error containing %q", err, tc.wantErrSubstr)
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
		"subject-access-review-cache-allow-ttl": {
			wantErrSubstr: "--subject-access-review-cache-allow-ttl must not be negative",
			set:           func(o *Options, ttl time.Duration) { o.App.SubjectAccessReviewAllowCacheTTL = ttl },
		},
		"subject-access-review-cache-deny-ttl": {
			wantErrSubstr: "--subject-access-review-cache-deny-ttl must not be negative",
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

func TestValidate_MaxImpersonationHeaderValues(t *testing.T) {
	const wantErrSubstr = "--max-impersonation-header-values must be greater than 0"

	tests := map[string]struct {
		max     int
		wantErr bool
	}{
		"default is valid":         {max: subjectaccessreview.DefaultMaxHeaderValues, wantErr: false},
		"custom positive is valid": {max: 1, wantErr: false},
		"zero is rejected":         {max: 0, wantErr: true},
		"negative is rejected":     {max: -1, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := New()
			cmd := &cobra.Command{}
			o.AddFlags(cmd)

			o.App.MaxImpersonationHeaderValues = tc.max

			err := o.Validate(cmd)
			gotErr := err != nil && strings.Contains(err.Error(), wantErrSubstr)
			if gotErr != tc.wantErr {
				t.Errorf("Validate() max header values error present = %v (err=%v), want %v", gotErr, err, tc.wantErr)
			}
		})
	}
}
