// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"io"
	"testing"

	"github.com/spf13/cobra"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

func TestLoggingOptionsDefaultsAndValidation(t *testing.T) {
	nfs := new(cliflag.NamedFlagSets)
	o := NewLoggingOptions(nfs)
	if o.Format != "json" {
		t.Fatalf("default format = %q", o.Format)
	}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	o.Format = "yaml"
	if err := o.Validate(); err == nil {
		t.Fatal("yaml accepted")
	}
}

func TestLoggingOptionsReadsVerbosityFromGlobalFlags(t *testing.T) {
	nfs := new(cliflag.NamedFlagSets)
	globalflag.AddGlobalFlags(nfs.FlagSet("Misc"), "test")
	o := NewLoggingOptions(nfs)
	if err := nfs.FlagSet("Misc").Set("v", "3"); err != nil {
		t.Fatal(err)
	}
	if got := o.Verbosity(); got != 3 {
		t.Fatalf("Verbosity() = %d, want 3", got)
	}
}

// TestLoggingFlagsReachOptionsThroughTheCommand pins the path RunE actually
// takes: the flags are merged onto the command from every named set, parsed,
// and read back off the options. The unit tests above exercise LoggingOptions
// in isolation, which would not notice --logging-format binding to a flag
// registered by some other set.
func TestLoggingFlagsReachOptionsThroughTheCommand(t *testing.T) {
	o := New()
	cmd := &cobra.Command{Use: "test"}
	o.AddFlags(cmd)

	if err := cmd.ParseFlags([]string{"--logging-format=text", "--v=4"}); err != nil {
		t.Fatal(err)
	}
	if o.Logging.Format != "text" {
		t.Fatalf("Format = %q, want text", o.Logging.Format)
	}
	if got := o.Logging.Verbosity(); got != 4 {
		t.Fatalf("Verbosity() = %d, want 4", got)
	}
	if got := o.Logging.ToLoggerOptions(io.Discard); got.Format != logging.FormatText || got.Verbosity != 4 {
		t.Fatalf("ToLoggerOptions = %+v", got)
	}

	// The aggregate must surface a bad format, not just the standalone Validate.
	o.Logging.Format = "yaml"
	if err := o.Validate(cmd); err == nil {
		t.Fatal("Options.Validate accepted --logging-format=yaml")
	}
}
