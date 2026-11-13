// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

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

// TestToRESTConfigLoadsTheKubeconfigAndAppliesOverrides pins that the
// explicit --kubeconfig is loaded and that an override flag wins over it.
func TestToRESTConfigLoadsTheKubeconfigAndAppliesOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kubeconfig")
	kubeconfig := `apiVersion: v1
kind: Config
clusters:
- name: demo
  cluster:
    server: https://kubeconfig.example.test:6443
    insecure-skip-tls-verify: true
contexts:
- name: demo
  context:
    cluster: demo
    user: demo
current-context: demo
users:
- name: demo
  user:
    token: from-kubeconfig
`
	if err := os.WriteFile(path, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	o := New()
	cmd := &cobra.Command{Use: "test"}
	o.AddFlags(cmd)
	if err := cmd.ParseFlags([]string{"--kubeconfig=" + path}); err != nil {
		t.Fatal(err)
	}
	cfg, err := o.Client.ToRESTConfig()
	if err != nil {
		t.Fatalf("ToRESTConfig() error = %v", err)
	}
	if cfg.Host != "https://kubeconfig.example.test:6443" || cfg.BearerToken != "from-kubeconfig" {
		t.Fatalf("config = host %q token %q", cfg.Host, cfg.BearerToken)
	}

	if err := cmd.ParseFlags([]string{"--token=from-flag"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = o.Client.ToRESTConfig()
	if err != nil {
		t.Fatalf("ToRESTConfig() with override error = %v", err)
	}
	if cfg.BearerToken != "from-flag" {
		t.Fatalf("BearerToken = %q, want the --token override", cfg.BearerToken)
	}
}
