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
	k8sErrors "k8s.io/apimachinery/pkg/util/errors"

	cliflag "k8s.io/component-base/cli/flag"
)

const (
	AppName = "kube-oidc-proxy"
)

type Options struct {
	App                  *KubeOIDCProxyOptions
	OIDCAuthentication   *OIDCAuthenticationOptions
	AuthenticationConfig *AuthenticationConfigOptions
	SecureServing        *SecureServingOptions
	Audit                *AuditOptions
	Client               *ClientOptions
	Misc                 *MiscOptions

	nfs *cliflag.NamedFlagSets
}

func New() *Options {
	nfs := new(cliflag.NamedFlagSets)

	// Add flags to command sets
	return &Options{
		App:                  NewKubeOIDCProxyOptions(nfs),
		OIDCAuthentication:   NewOIDCAuthenticationOptions(nfs),
		AuthenticationConfig: NewAuthenticationConfigOptions(nfs),
		SecureServing:        NewSecureServingOptions(nfs),
		Audit:                NewAuditOptions(nfs),
		Client:               NewClientOptions(nfs),
		Misc:                 NewMiscOptions(nfs),

		nfs: nfs,
	}
}

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

func (o *Options) Validate(cmd *cobra.Command) error {
	if cmd.Flag("version").Value.String() == "true" {
		o.Misc.PrintVersionAndExit()
	}

	var errs []error

	if err := o.AuthenticationConfig.Validate(); err != nil {
		errs = append(errs, err)
	}

	authConfigSet := o.AuthenticationConfig.ConfigFile != ""

	if authConfigSet && o.oidcFlagsChanged(cmd) {
		errs = append(errs, fmt.Errorf("authentication-config and issuer-specific --oidc-* flags are mutually exclusive"))
	}

	if err := o.OIDCAuthentication.Validate(authConfigSet); err != nil {
		errs = append(errs, err)
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

	if o.App.DisableImpersonation &&
		(o.App.ExtraHeaderOptions.EnableClientIPExtraUserHeader || len(o.App.ExtraHeaderOptions.ExtraUserHeaders) > 0) {
		errs = append(errs, errors.New("cannot add extra user headers when impersonation disabled"))
	}

	if o.App.TokenPassthrough.Enabled && o.App.TokenPassthrough.RequestTimeout <= 0 {
		errs = append(errs, errors.New("--token-passthrough-request-timeout must be greater than zero"))
	}

	if o.App.SubjectAccessReviewTimeout <= 0 {
		errs = append(errs, fmt.Errorf("--subject-access-review-timeout must be greater than 0, got %s", o.App.SubjectAccessReviewTimeout))
	}

	if o.App.MaxImpersonationHeaderValues <= 0 {
		errs = append(errs, fmt.Errorf("--max-impersonation-header-values must be greater than 0, got %d", o.App.MaxImpersonationHeaderValues))
	}

	if len(errs) > 0 {
		return k8sErrors.NewAggregate(errs)
	}

	return nil
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
