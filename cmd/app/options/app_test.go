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
		"SubjectAccessReviewTimeout":                       {app.SubjectAccessReviewTimeout, 7 * time.Second},
		"SubjectAccessReviewAllowCacheTTL":                 {app.SubjectAccessReviewAllowCacheTTL, time.Minute},
		"SubjectAccessReviewDenyCacheTTL":                  {app.SubjectAccessReviewDenyCacheTTL, 2 * time.Minute},
		"MaxImpersonationHeaderValues":                     {app.MaxImpersonationHeaderValues, 8},
		"TrustedProxies":                                   {app.TrustedProxies, []string{"10.0.0.0/8", "192.168.0.0/16"}},
		"AllowedReservedGroups":                            {app.AllowedReservedGroups, []string{"system:nodes"}},
		"TokenPassthrough.Enabled":                         {app.TokenPassthrough.Enabled, true},
		"TokenPassthrough.Audiences":                       {app.TokenPassthrough.Audiences, []string{"aud1", "aud2"}},
		"TokenPassthrough.RequestTimeout":                  {app.TokenPassthrough.RequestTimeout, 3 * time.Second},
		"TokenPassthrough.CacheSuccessTTL":                 {app.TokenPassthrough.CacheSuccessTTL, 4 * time.Second},
		"TokenPassthrough.CacheFailureTTL":                 {app.TokenPassthrough.CacheFailureTTL, 5 * time.Second},
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
	if o.App.TokenPassthrough.RequestTimeout != 10*time.Second {
		t.Errorf("TokenPassthrough.RequestTimeout = %s, want 10s", o.App.TokenPassthrough.RequestTimeout)
	}
}

// TestClientFlagsChanged pins which flags select the kubeconfig path over the
// in-cluster configuration: the connection flags do, the throttling flags and
// unrelated flags do not.
func TestClientFlagsChanged(t *testing.T) {
	tests := map[string]struct {
		args []string
		want bool
	}{
		"no flags":        {want: false},
		"kubeconfig":      {args: []string{"--kubeconfig=/tmp/kubeconfig"}, want: true},
		"server":          {args: []string{"--server=https://api.example.com"}, want: true},
		"token":           {args: []string{"--token=abc"}, want: true},
		"context":         {args: []string{"--context=dev"}, want: true},
		"throttling only": {args: []string{"--kube-client-qps=5", "--kube-client-burst=10"}, want: false},
		"unrelated flag":  {args: []string{"--secure-port=8443"}, want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := New()
			cmd := &cobra.Command{Use: "test"}
			o.AddFlags(cmd)
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			if got := o.Client.ClientFlagsChanged(cmd); got != tc.want {
				t.Errorf("ClientFlagsChanged(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}

	// The proxy impersonates on the client's behalf; it must never be told to
	// impersonate on its own, so the client flag set does not offer --as.
	o := New()
	cmd := &cobra.Command{Use: "test"}
	o.AddFlags(cmd)
	for _, flag := range []string{"as", "as-uid", "as-group"} {
		if cmd.Flags().Lookup(flag) != nil {
			t.Errorf("--%s is offered; the proxy must not impersonate on its own calls", flag)
		}
	}
	for _, flag := range clientOptionFlags() {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("--%s is listed as a client flag but not registered", flag)
		}
	}
}
