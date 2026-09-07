// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestMetricsOptionsDisabledByDefault(t *testing.T) {
	o := New()
	if o.Metrics.Enabled() {
		t.Fatal("metrics enabled with no flag")
	}
	if err := o.Metrics.Validate(); err != nil {
		t.Fatalf("Validate on the default = %v", err)
	}
}

func TestMetricsOptionsParseAndValidate(t *testing.T) {
	tests := map[string]struct {
		bind    string
		enabled bool
		port    int
		wantErr string
	}{
		"empty is disabled": {bind: "", enabled: false},
		"zero is disabled":  {bind: "0", enabled: false},
		"port only":         {bind: ":9090", enabled: true, port: 9090},
		"loopback":          {bind: "127.0.0.1:9090", enabled: true, port: 9090},
		"ipv6":              {bind: "[::1]:9090", enabled: true, port: 9090},
		"missing port":      {bind: "127.0.0.1", wantErr: "host:port"},
		"port out of range": {bind: ":70000", wantErr: "port"},
		"non-numeric port":  {bind: ":metrics", wantErr: "port"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			m := &MetricsOptions{BindAddress: tc.bind}
			err := m.Validate()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Validate(%q) = %v, want error containing %q", tc.bind, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(%q) = %v", tc.bind, err)
			}
			if m.Enabled() != tc.enabled {
				t.Fatalf("Enabled() = %v, want %v", m.Enabled(), tc.enabled)
			}
			if tc.enabled {
				port, err := m.Port()
				if err != nil || port != tc.port {
					t.Fatalf("Port() = %d, %v; want %d", port, err, tc.port)
				}
			}
		})
	}
}

func TestMetricsFlagReachesOptionsThroughTheCommand(t *testing.T) {
	o := New()
	cmd := &cobra.Command{Use: "x"}
	o.AddFlags(cmd)
	if err := cmd.ParseFlags([]string{"--metrics-bind-address=0.0.0.0:9090"}); err != nil {
		t.Fatal(err)
	}
	if o.Metrics.BindAddress != "0.0.0.0:9090" || !o.Metrics.Enabled() {
		t.Fatalf("BindAddress = %q, Enabled = %v", o.Metrics.BindAddress, o.Metrics.Enabled())
	}

	// "0" is the kubebuilder spelling of disabled and must validate cleanly.
	o = New()
	cmd = &cobra.Command{Use: "x"}
	o.AddFlags(cmd)
	if err := cmd.ParseFlags([]string{"--metrics-bind-address=0"}); err != nil {
		t.Fatal(err)
	}
	if o.Metrics.Enabled() {
		t.Fatal("\"0\" must disable the listener")
	}
	if err := o.Metrics.Validate(); err != nil {
		t.Fatalf("Validate(\"0\") = %v, want nil", err)
	}
}

func TestValidateRejectsMetricsPortCollisions(t *testing.T) {
	for _, tc := range []struct{ name, bind, want string }{
		{"readiness port", ":8080", "readiness probe"},
		{"secure port", ":6443", "secure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := New()
			cmd := &cobra.Command{Use: "x"}
			o.AddFlags(cmd)
			if err := cmd.ParseFlags([]string{
				"--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=c",
				"--metrics-bind-address=" + tc.bind,
			}); err != nil {
				t.Fatal(err)
			}
			err := o.Validate(cmd)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

// TestValidateAggregatesMetricsErrorsWithOthers pins that a metrics error is
// one entry in the aggregate, not a short-circuit that hides other mistakes.
func TestValidateAggregatesMetricsErrorsWithOthers(t *testing.T) {
	o := New()
	cmd := &cobra.Command{Use: "x"}
	o.AddFlags(cmd)
	if err := cmd.ParseFlags([]string{
		"--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=c",
		"--metrics-bind-address=:0", "--logging-format=yaml",
	}); err != nil {
		t.Fatal(err)
	}
	err := o.Validate(cmd)
	if err == nil {
		t.Fatal("Validate accepted port 0 and an unknown logging format")
	}
	for _, want := range []string{"--metrics-bind-address", "logging"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate error %q lacks %q", err, want)
		}
	}
}

func TestMiscCommitReportsTheBuildCommit(t *testing.T) {
	o := New()
	if o.Misc.Commit() != gitCommit {
		t.Fatalf("Commit() = %q, want the ldflags value %q", o.Misc.Commit(), gitCommit)
	}
}
