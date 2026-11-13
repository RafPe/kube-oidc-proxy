// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"strings"
	"testing"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview"
)

// TestValidate_TokenPassthroughCacheTTLs pins that the cache TTL flags reject
// negative values regardless of whether --token-passthrough is enabled, so a
// broken value cannot lie dormant until the feature is switched on. Zero stays
// valid: it disables that class of caching.
func TestValidate_TokenPassthroughCacheTTLs(t *testing.T) {
	tests := map[string]struct {
		successTTL         time.Duration
		failureTTL         time.Duration
		passthroughEnabled bool
		wantErr            string
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
			wantErr:            "--token-passthrough-cache-success-ttl must not be negative",
		},
		"negative failure TTL is rejected": {
			successTTL:         10 * time.Second,
			failureTTL:         -1 * time.Second,
			passthroughEnabled: true,
			wantErr:            "--token-passthrough-cache-failure-ttl must not be negative",
		},
		"negative success TTL is rejected even with passthrough disabled": {
			successTTL: -1 * time.Second,
			failureTTL: 10 * time.Second,
			wantErr:    "--token-passthrough-cache-success-ttl must not be negative",
		},
		"negative failure TTL is rejected even with passthrough disabled": {
			successTTL: 10 * time.Second,
			failureTTL: -1 * time.Second,
			wantErr:    "--token-passthrough-cache-failure-ttl must not be negative",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o, cmd := newTestOptions(t)

			o.App.TokenPassthrough.Enabled = tc.passthroughEnabled
			o.App.TokenPassthrough.SuccessCacheTTL = tc.successTTL
			o.App.TokenPassthrough.FailureCacheTTL = tc.failureTTL

			if tc.wantErr == "" {
				checkValidateError(t, o.Validate(cmd))
			} else {
				checkValidateError(t, o.Validate(cmd), tc.wantErr)
			}
		})
	}
}

// TestValidate_TokenPassthroughRequestTimeout pins that a non-positive
// --token-passthrough-request-timeout is rejected whether or not
// --token-passthrough is enabled, like the cache TTLs beside it.
func TestValidate_TokenPassthroughRequestTimeout(t *testing.T) {
	const wantErr = "--token-passthrough-request-timeout must be greater than 0"

	for name, tc := range map[string]struct {
		timeout            time.Duration
		passthroughEnabled bool
		wantErr            bool
	}{
		"default is valid":                          {timeout: 10 * time.Second},
		"zero is rejected":                          {timeout: 0, passthroughEnabled: true, wantErr: true},
		"zero is rejected with passthrough off":     {timeout: 0, wantErr: true},
		"negative is rejected with passthrough off": {timeout: -time.Second, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			o, cmd := newTestOptions(t)

			o.App.TokenPassthrough.Enabled = tc.passthroughEnabled
			o.App.TokenPassthrough.Timeout = tc.timeout

			if tc.wantErr {
				checkValidateError(t, o.Validate(cmd), wantErr)
			} else {
				checkValidateError(t, o.Validate(cmd))
			}
		})
	}
}

func TestValidate_SubjectAccessReviewTimeout(t *testing.T) {
	const wantErr = "--subject-access-review-timeout must be greater than 0"

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
			o, cmd := newTestOptions(t)

			o.App.SubjectAccessReview.Timeout = tc.timeout

			if tc.wantErr {
				checkValidateError(t, o.Validate(cmd), wantErr)
			} else {
				checkValidateError(t, o.Validate(cmd))
			}
		})
	}
}

func TestValidate_SubjectAccessReviewCacheTTLs(t *testing.T) {
	flags := map[string]struct {
		wantErr string
		set     func(o *Options, ttl time.Duration)
	}{
		"subject-access-review-cache-allow-ttl": {
			wantErr: "--subject-access-review-cache-allow-ttl must not be negative",
			set:     func(o *Options, ttl time.Duration) { o.App.SubjectAccessReview.AllowCacheTTL = ttl },
		},
		"subject-access-review-cache-deny-ttl": {
			wantErr: "--subject-access-review-cache-deny-ttl must not be negative",
			set:     func(o *Options, ttl time.Duration) { o.App.SubjectAccessReview.DenyCacheTTL = ttl },
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
					o, cmd := newTestOptions(t)

					flag.set(o, tc.ttl)

					if tc.wantErr {
						checkValidateError(t, o.Validate(cmd), flag.wantErr)
					} else {
						checkValidateError(t, o.Validate(cmd))
					}
				})
			}
		})
	}
}

func TestValidate_MaxImpersonationHeaderValues(t *testing.T) {
	const wantErr = "--max-impersonation-header-values must be greater than 0"

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
			o, cmd := newTestOptions(t)

			o.App.MaxImpersonationHeaderValues = tc.max

			if tc.wantErr {
				checkValidateError(t, o.Validate(cmd), wantErr)
			} else {
				checkValidateError(t, o.Validate(cmd))
			}
		})
	}
}

// TestValidate_SecurePortCollidesWithReadinessProbe pins that the secure
// port and the readiness probe cannot share a port, reported by both flags.
func TestValidate_SecurePortCollidesWithReadinessProbe(t *testing.T) {
	o, cmd := newTestOptions(t)
	if err := cmd.ParseFlags([]string{"--secure-port=8080", "--readiness-probe-port=8080"}); err != nil {
		t.Fatal(err)
	}
	checkValidateError(t, o.Validate(cmd), "--secure-port 8080 is already used by --readiness-probe-port")
}

// TestValidate_MetricsBindAddressPortCollisions pins that the metrics listener
// cannot be pointed at a port the process already binds. Both collisions are
// reported by port number, and a disabled listener is never checked -- "0" is
// a disabled listener, not a port.
func TestValidate_MetricsBindAddressPortCollisions(t *testing.T) {
	tests := map[string]struct {
		bindAddress string
		probePort   int
		securePort  int
		wantErr     string
	}{
		"collides with the readiness probe port": {
			bindAddress: ":8080",
			probePort:   8080,
			securePort:  6443,
			wantErr:     "--metrics-bind-address port 8080 is already used by --readiness-probe-port",
		},
		"collides with the secure serving port": {
			bindAddress: "127.0.0.1:6443",
			probePort:   8080,
			securePort:  6443,
			wantErr:     "--metrics-bind-address port 6443 is already used by --secure-port",
		},
		"a distinct port is accepted": {
			bindAddress: ":9090",
			probePort:   8080,
			securePort:  6443,
		},
		"a disabled listener is not compared with either port": {
			bindAddress: "0",
			probePort:   8080,
			securePort:  6443,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o, cmd := newTestOptions(t)

			o.Metrics.BindAddress = tc.bindAddress
			o.App.ReadinessProbePort = tc.probePort
			o.SecureServing.BindPort = tc.securePort

			if tc.wantErr == "" {
				checkValidateError(t, o.Validate(cmd))
			} else {
				checkValidateError(t, o.Validate(cmd), tc.wantErr)
			}
		})
	}
}

// TestValidate_ReportsEveryFlagErrorAtOnce pins that Validate is the one
// place flag errors are reported: mistakes in unrelated groups, including the
// checks that used to run only once the proxy was being built, come back
// together, and every message names its flag with the -- prefix.
func TestValidate_ReportsEveryFlagErrorAtOnce(t *testing.T) {
	o, cmd := newTestOptions(t)
	if err := cmd.ParseFlags([]string{
		"--subject-access-review-timeout=0",
		"--oidc-username-prefix=system:",
		"--oidc-issuer-url=https://issuer.example.com",
		"--trusted-proxies=bogus",
		"--allow-reserved-groups=admins",
	}); err != nil {
		t.Fatal(err)
	}

	err := o.Validate(cmd)
	checkValidateError(t, err,
		"--subject-access-review-timeout must be greater than 0",
		"--oidc-username-prefix",
		"--oidc-issuer-url and --oidc-client-id must be specified together",
		"--trusted-proxies",
		"--allow-reserved-groups",
	)

	for _, e := range flatten(err) {
		if !strings.HasPrefix(e.Error(), "--") {
			t.Errorf("error %q does not start with the --flag it concerns", e)
		}
	}
}

// flatten returns the leaves of a tree of joined errors.
func flatten(err error) []error {
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return []error{err}
	}
	var leaves []error
	for _, e := range joined.Unwrap() {
		leaves = append(leaves, flatten(e)...)
	}
	return leaves
}
