// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestVersionOptionsReportBuildInformation pins that the ldflags-stamped
// values are what the startup record and build_info report, and that
// --version is detected without being acted on by the options themselves.
func TestVersionOptionsReportBuildInformation(t *testing.T) {
	o := New()
	cmd := &cobra.Command{Use: "test"}
	o.AddFlags(cmd)

	if o.Version.Version() != gitVersion || o.Version.Commit() != gitCommit {
		t.Fatalf("Version()/Commit() = %q/%q, want %q/%q", o.Version.Version(), o.Version.Commit(), gitVersion, gitCommit)
	}

	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if o.Version.Requested(cmd) {
		t.Fatal("--version reported as requested without the flag")
	}
	if err := cmd.ParseFlags([]string{"--version"}); err != nil {
		t.Fatal(err)
	}
	if !o.Version.Requested(cmd) {
		t.Fatal("--version was given but not reported as requested")
	}
	// Validate must stay a pure validator: --version is the command's to act on.
	if err := o.Validate(cmd); err != nil {
		t.Fatalf("Validate() with --version = %v, want nil", err)
	}
}
