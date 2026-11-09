// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"
)

// AuthenticationConfigOptions select multi-issuer mode: the path of an
// AuthenticationConfiguration document, which authn.LoadConfiguration reads.
type AuthenticationConfigOptions struct {
	ConfigFile string
}

// NewAuthenticationConfigOptions registers the Authentication Config flag set
// on nfs and returns the options it binds.
func NewAuthenticationConfigOptions(nfs *cliflag.NamedFlagSets) *AuthenticationConfigOptions {
	return new(AuthenticationConfigOptions).AddFlags(nfs.FlagSet("Authentication Config"))
}

// AddFlags binds --authentication-config to fs and returns o for chaining.
func (o *AuthenticationConfigOptions) AddFlags(fs *pflag.FlagSet) *AuthenticationConfigOptions {
	fs.StringVar(&o.ConfigFile, "authentication-config", o.ConfigFile,
		"Path to a file containing an AuthenticationConfiguration "+
			"(apiserver.config.k8s.io/v1 or v1beta1) enabling multi-issuer OIDC "+
			"authentication. This flag is mutually exclusive with the --oidc-* flags.")
	return o
}

// Validate checks that a configured document exists. Its content is
// validated when the authenticators are built.
func (o *AuthenticationConfigOptions) Validate() error {
	if o.ConfigFile == "" {
		return nil
	}
	if _, err := os.Stat(o.ConfigFile); err != nil {
		return fmt.Errorf("--authentication-config file %q: %w", o.ConfigFile, err)
	}
	return nil
}
