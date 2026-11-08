// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// LoggingOptions configures the process-wide root logger. Verbosity is
// deliberately NOT a flag of its own: -v is the single knob, registered by
// globalflag in the Global flag set (GlobalFlagSet), and is read back from there so the two can never
// disagree.
type LoggingOptions struct {
	// Format is the encoding of the log stream, one of json or text.
	Format logging.Format

	// nfs is the flag-set registry the command was built from, kept so
	// Verbosity can read -v from the Global flag set at call time rather than
	// snapshotting it before the command line is parsed.
	nfs *cliflag.NamedFlagSets
}

// NewLoggingOptions registers the Logging flag set on nfs and returns the
// options it binds.
func NewLoggingOptions(nfs *cliflag.NamedFlagSets) *LoggingOptions {
	l := &LoggingOptions{nfs: nfs}
	return l.AddFlags(nfs.FlagSet("Logging"))
}

// AddFlags binds --logging-format to fs and returns o for chaining.
func (o *LoggingOptions) AddFlags(fs *pflag.FlagSet) *LoggingOptions {
	fs.StringVar((*string)(&o.Format), "logging-format", string(logging.FormatJSON), "Log output format, one of json or text.")
	return o
}

// Validate rejects a format the root logger cannot build. An empty value is
// refused too: the flag defaults to json, so an empty one was set explicitly.
func (o *LoggingOptions) Validate() error {
	switch o.Format {
	case logging.FormatJSON, logging.FormatText:
		return nil
	default:
		return fmt.Errorf("--logging-format must be %q or %q, got %q",
			logging.FormatJSON, logging.FormatText, o.Format)
	}
}

// Verbosity returns the -v value the command line carries, or 0 when the flag
// is absent. -v is owned by globalflag in the Global flag set; it is read here
// rather than bound to a field of its own so that klog and the root logger are
// driven by exactly one value.
func (o *LoggingOptions) Verbosity() int {
	if o.nfs == nil {
		return 0
	}
	f := o.nfs.FlagSet(GlobalFlagSet).Lookup("v")
	if f == nil {
		return 0
	}
	v, err := strconv.Atoi(f.Value.String())
	if err != nil {
		return 0
	}
	return v
}

// ToLoggerOptions renders the flags as the root logger's options, writing to w.
func (o *LoggingOptions) ToLoggerOptions(w io.Writer) logging.Options {
	return logging.Options{
		Format:    o.Format,
		Verbosity: o.Verbosity(),
		Output:    w,
	}
}
