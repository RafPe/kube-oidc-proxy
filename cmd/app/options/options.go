// Copyright Jetstack Ltd. See LICENSE for details.

// Package options defines the command-line flags and configuration structures
// for the kube-oidc-proxy binary.
package options

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

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
	SecureServing        *SecureServingOptions
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
		SecureServing:        NewSecureServingOptions(nfs),
		Audit:                newAuditOptions(nfs),
		Client:               NewClientOptions(nfs),
		Logging:              NewLoggingOptions(nfs),
		Metrics:              NewMetricsOptions(nfs),
		Version:              NewVersionOptions(nfs),

		nfs: nfs,
	}
}

// AddFlags adds every registered flag set to cmd and installs the sectioned
// help and usage output.
func (o *Options) AddFlags(cmd *cobra.Command) {
	// pretty output from kube-apiserver
	usageFmt := "Usage:\n  %s\n"
	cols, _, _ := term.GetSize(0)
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), *o.nfs, cols)
		return nil
	})

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), *o.nfs, cols)
	})

	fs := cmd.Flags()
	for _, f := range o.nfs.FlagSets {
		fs.AddFlagSet(f)
	}
}

// Validate checks the parsed options and returns every problem found, joined.
func (o *Options) Validate(cmd *cobra.Command) error {
	var errs []error

	if err := o.AuthenticationConfig.Validate(); err != nil {
		errs = append(errs, err)
	}

	authConfigSet := o.AuthenticationConfig.ConfigFile != ""

	if authConfigSet && o.oidcFlagsChanged(cmd) {
		errs = append(errs, fmt.Errorf("authentication-config and issuer-specific --oidc-* flags are mutually exclusive"))
	}

	if err := o.OIDCAuthentication.Validate(); err != nil {
		errs = append(errs, err)
	}
	if !authConfigSet {
		if err := o.OIDCAuthentication.ValidateIssuerFlags(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := o.SecureServing.Validate(); len(err) > 0 {
		errs = append(errs, err...)
	}

	if o.SecureServing.BindPort == o.App.ReadinessProbePort {
		errs = append(errs, fmt.Errorf("unable to securely serve on port %d (used by readiness probe)", o.SecureServing.BindPort))
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
			errs = append(errs, fmt.Errorf("--metrics-bind-address port %d is already used by the readiness probe", port))
		}
		if port == o.SecureServing.BindPort {
			errs = append(errs, fmt.Errorf("--metrics-bind-address port %d is already used by the secure serving port", port))
		}
	}

	if err := o.App.Validate(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// newAuditOptions binds the apiserver's own audit flags under the Audit flag
// set. The proxy adds nothing to them, so it holds the apiserver type
// directly.
func newAuditOptions(nfs *cliflag.NamedFlagSets) *apiserveroptions.AuditOptions {
	a := apiserveroptions.NewAuditOptions()
	a.AddFlags(nfs.FlagSet("Audit"))
	return a
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
