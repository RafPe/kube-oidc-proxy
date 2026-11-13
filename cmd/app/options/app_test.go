// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"reflect"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// TestProxyFlagsReachOptionsThroughTheCommand pins the binding of every proxy
// option group's flags through the command, the way the logging and metrics
// tests do for theirs: a flag registered under one name but read from another
// field would silently keep its default.
func TestProxyFlagsReachOptionsThroughTheCommand(t *testing.T) {
	o := New()
	cmd := &cobra.Command{Use: "test"}
	o.AddFlags(cmd)

	if err := cmd.ParseFlags([]string{
		"--disable-impersonation",
		"--readiness-probe-port=9090",
		"--readiness-require-all-issuers",
		"--flush-interval=25ms",
		"--subject-access-review-timeout=7s",
		"--subject-access-review-cache-allow-ttl=1m",
		"--subject-access-review-cache-deny-ttl=2m",
		"--max-impersonation-header-values=8",
		"--trusted-proxies=10.0.0.0/8,192.168.0.0/16",
		"--allow-reserved-groups=system:nodes",
		"--token-passthrough",
		"--token-passthrough-audiences=aud1,aud2",
		"--token-passthrough-request-timeout=3s",
		"--token-passthrough-cache-success-ttl=4s",
		"--token-passthrough-cache-failure-ttl=5s",
		"--extra-user-header-client-ip",
		"--extra-user-headers=team=platform,team=infra,region=eu",
	}); err != nil {
		t.Fatal(err)
	}

	app := o.App
	checks := map[string]struct{ got, want any }{
		"DisableImpersonation":                             {app.DisableImpersonation, true},
		"ReadinessProbePort":                               {app.ReadinessProbePort, 9090},
		"ReadinessRequireAllIssuers":                       {app.ReadinessRequireAllIssuers, true},
		"FlushInterval":                                    {app.FlushInterval, 25 * time.Millisecond},
		"SubjectAccessReview.Timeout":                      {app.SubjectAccessReview.Timeout, 7 * time.Second},
		"SubjectAccessReview.AllowCacheTTL":                {app.SubjectAccessReview.AllowCacheTTL, time.Minute},
		"SubjectAccessReview.DenyCacheTTL":                 {app.SubjectAccessReview.DenyCacheTTL, 2 * time.Minute},
		"MaxImpersonationHeaderValues":                     {app.MaxImpersonationHeaderValues, 8},
		"TrustedProxies":                                   {app.TrustedProxies, []string{"10.0.0.0/8", "192.168.0.0/16"}},
		"AllowedReservedGroups":                            {app.AllowedReservedGroups, []string{"system:nodes"}},
		"TokenPassthrough.Enabled":                         {app.TokenPassthrough.Enabled, true},
		"TokenPassthrough.Audiences":                       {app.TokenPassthrough.Audiences, []string{"aud1", "aud2"}},
		"TokenPassthrough.Timeout":                         {app.TokenPassthrough.Timeout, 3 * time.Second},
		"TokenPassthrough.SuccessCacheTTL":                 {app.TokenPassthrough.SuccessCacheTTL, 4 * time.Second},
		"TokenPassthrough.FailureCacheTTL":                 {app.TokenPassthrough.FailureCacheTTL, 5 * time.Second},
		"ExtraHeaderOptions.EnableClientIPExtraUserHeader": {app.ExtraHeaderOptions.EnableClientIPExtraUserHeader, true},
		"ExtraHeaderOptions.ExtraUserHeaders": {app.ExtraHeaderOptions.ExtraUserHeaders,
			map[string][]string{"team": {"platform", "infra"}, "region": {"eu"}}},
	}
	for name, c := range checks {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s = %#v, want %#v", name, c.got, c.want)
		}
	}
}

// TestProxyFlagDefaults pins the defaults the chart and the docs rely on.
func TestProxyFlagDefaults(t *testing.T) {
	o := New()
	cmd := &cobra.Command{Use: "test"}
	o.AddFlags(cmd)
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}

	if o.App.ReadinessProbePort != 8080 {
		t.Errorf("ReadinessProbePort = %d, want 8080", o.App.ReadinessProbePort)
	}
	if o.App.FlushInterval != 50*time.Millisecond {
		t.Errorf("FlushInterval = %s, want 50ms", o.App.FlushInterval)
	}
	if o.App.TokenPassthrough.Enabled {
		t.Error("token passthrough is enabled by default")
	}
	if o.App.TokenPassthrough.Timeout != 10*time.Second {
		t.Errorf("TokenPassthrough.Timeout = %s, want 10s", o.App.TokenPassthrough.Timeout)
	}
}
