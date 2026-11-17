// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestSecureServingDefaultsAndFlags pins the defaults the chart relies on and
// that the apiserver's serving flags are bound under the Secure Serving set.
func TestSecureServingDefaultsAndFlags(t *testing.T) {
	o := New()
	cmd := &cobra.Command{Use: "test"}
	o.AddFlags(cmd)

	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if o.SecureServing.BindPort != 6443 || o.SecureServing.BindAddress.String() != "0.0.0.0" {
		t.Fatalf("defaults = %s:%d, want 0.0.0.0:6443", o.SecureServing.BindAddress, o.SecureServing.BindPort)
	}
	if o.SecureServing.ServerCert.PairName != AppName {
		t.Fatalf("certificate pair name = %q, want %q", o.SecureServing.ServerCert.PairName, AppName)
	}

	if err := cmd.ParseFlags([]string{"--secure-port=8443", "--bind-address=127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if o.SecureServing.BindPort != 8443 || o.SecureServing.BindAddress.String() != "127.0.0.1" {
		t.Fatalf("flags = %s:%d, want 127.0.0.1:8443", o.SecureServing.BindAddress, o.SecureServing.BindPort)
	}
}
