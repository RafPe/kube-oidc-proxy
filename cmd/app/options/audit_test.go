// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestAuditFlagsReachOptionsThroughTheCommand pins that the apiserver's audit
// flags are bound under the Audit flag set and land on the embedded options.
func TestAuditFlagsReachOptionsThroughTheCommand(t *testing.T) {
	o := New()
	cmd := &cobra.Command{Use: "test"}
	o.AddFlags(cmd)

	if err := cmd.ParseFlags([]string{"--audit-log-path=/var/log/audit.log", "--audit-log-maxage=7"}); err != nil {
		t.Fatal(err)
	}
	if o.Audit.LogOptions.Path != "/var/log/audit.log" {
		t.Errorf("audit log path = %q", o.Audit.LogOptions.Path)
	}
	if o.Audit.LogOptions.MaxAge != 7 {
		t.Errorf("audit log max age = %d, want 7", o.Audit.LogOptions.MaxAge)
	}
	if errs := o.Audit.Validate(); len(errs) != 0 {
		t.Errorf("Validate() = %v", errs)
	}
}
