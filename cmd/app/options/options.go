// Copyright Jetstack Ltd. See LICENSE for details.

// Package options defines the command-line flags and configuration structures
// for the kube-oidc-proxy binary.
package options

import (
	"io"
	"os"

	"errors"
	"fmt"

	"golang.org/x/term"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	apiserveroptions "k8s.io/apiserver/pkg/server/options"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
)

const (
	AppName = "kube-oidc-proxy"
)

// Options is every flag the proxy binary accepts, grouped by concern. Each
// group registers its own flag set and validates its own fields; Validate adds
// the checks that span groups.
type Options struct {
	App                  *KubeOIDCProxyOptions
	OIDCAuthentication   *OIDCAuthenticationOptions
	AuthenticationConfig *AuthenticationConfigOptions
	SecureServing        *apiserveroptions.SecureServingOptions
	Audit                *apiserveroptions.AuditOptions
	Client               *ClientOptions
	Logging              *LoggingOptions
	Metrics              *MetricsOptions
	Version              *VersionOptions

	nfs *cliflag.NamedFlagSets
}

// GlobalFlagSet names the flag set carrying the component-base global flags
// (-v, --vmodule and friends), which LoggingOptions reads the verbosity from.
const GlobalFlagSet = "Global"

// New registers every flag set and returns the options they bind to.
func New() *Options {
	nfs := new(cliflag.NamedFlagSets)
	globalflag.AddGlobalFlags(nfs.FlagSet(GlobalFlagSet), AppName)

	return &Options{
		App:                  NewKubeOIDCProxyOptions(nfs),
		OIDCAuthentication:   NewOIDCAuthenticationOptions(nfs),
		AuthenticationConfig: NewAuthenticationConfigOptions(nfs),
		SecureServing:        newSecureServingOptions(nfs),
		Audit:                newAuditOptions(nfs),
		Client:               NewClientOptions(nfs),
		Logging:              NewLoggingOptions(nfs),
		Metrics:              NewMetricsOptions(nfs),
		Version:              NewVersionOptions(nfs),

		nfs: nfs,
	}
}

// terminalWidth is the column count of the terminal w writes to, or 0 (no
// wrapping) when w is not a terminal. It measures the writer the help text
// goes to, not stdin, so redirected help is never wrapped to a stale width.
func terminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return 0
	}
	cols, _, err := term.GetSize(int(f.Fd()))
	if err != nil {
		return 0
	}
	return cols
}

// AddFlags adds every registered flag set to cmd and installs the sectioned
// help and usage output.
func (o *Options) AddFlags(cmd *cobra.Command) {
	// pretty output from kube-apiserver, wrapped to the width of the terminal
	// the text is written to (0, no wrapping, when it is not a terminal)
	usageFmt := "Usage:\n  %s\n"
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		out := cmd.OutOrStderr()
		cols := terminalWidth(out)
		_, _ = fmt.Fprintf(out, usageFmt, cmd.UseLine())
		cliflag.PrintSections(out, *o.nfs, cols)
		return nil
	})

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		out := cmd.OutOrStdout()
		cols := terminalWidth(out)
		_, _ = fmt.Fprintf(out, "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(out, *o.nfs, cols)
	})

	fs := cmd.Flags()
	for _, f := range o.nfs.FlagSets {
		fs.AddFlagSet(f)
	}
}

// Validate checks the parsed options and returns every problem found, joined.
// It is the one place a flag error is reported: everything that can be
// checked from the flag values alone is checked here, before anything is
// built, so an operator sees every mistake in one run.
func (o *Options) Validate(cmd *cobra.Command) error {
	var errs []error

	if err := o.AuthenticationConfig.Validate(); err != nil {
		errs = append(errs, err)
	}

	authConfigSet := o.AuthenticationConfig.ConfigFile != ""

	if authConfigSet && o.oidcFlagsChanged(cmd) {
		errs = append(errs, errors.New("--authentication-config and the issuer-specific --oidc-* flags are mutually exclusive"))
	}

	if err := o.OIDCAuthentication.Validate(); err != nil {
		errs = append(errs, err)
	}
	if !authConfigSet {
		if err := o.OIDCAuthentication.ValidateIssuerFlags(); err != nil {
			errs = append(errs, err)
		}
		errs = append(errs, o.OIDCAuthentication.validateIdentityPrefixes()...)
	}

	if err := o.SecureServing.Validate(); len(err) > 0 {
		errs = append(errs, err...)
	}

	if o.SecureServing.BindPort == o.App.ReadinessProbePort {
		errs = append(errs, fmt.Errorf("--secure-port %d is already used by --readiness-probe-port", o.SecureServing.BindPort))
	}

	if err := o.Audit.Validate(); len(err) > 0 {
		errs = append(errs, err...)
	}

	if err := o.Logging.Validate(); err != nil {
		errs = append(errs, err)
	}

	if err := o.Metrics.Validate(); err != nil {
		errs = append(errs, err)
	} else if o.Metrics.Enabled() {
		// Port() cannot fail here: Validate just accepted the address.
		port, _ := o.Metrics.Port()
		if port == o.App.ReadinessProbePort {
			errs = append(errs, fmt.Errorf("--metrics-bind-address port %d is already used by --readiness-probe-port", port))
		}
		if port == o.SecureServing.BindPort {
			errs = append(errs, fmt.Errorf("--metrics-bind-address port %d is already used by --secure-port", port))
		}
	}

	if err := o.App.Validate(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// oidcFlagsChanged reports whether any --oidc-* flag was set on cmd. The flag
// names are derived from the registered OIDC flag set so the list stays in sync
// with the flags defined in OIDCAuthenticationOptions.AddFlags automatically.
func (o *Options) oidcFlagsChanged(cmd *cobra.Command) bool {
	changed := false
	o.nfs.FlagSet("OIDC").VisitAll(func(f *pflag.Flag) {
		if f.Name == "oidc-tls-client-cert-file" || f.Name == "oidc-tls-client-key-file" {
			return
		}
		if cf := cmd.Flag(f.Name); cf != nil && cf.Changed {
			changed = true
		}
	})
	return changed
}
