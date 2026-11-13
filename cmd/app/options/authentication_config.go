// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"
)

type AuthenticationConfigOptions struct {
	ConfigFile string
}

func NewAuthenticationConfigOptions(nfs *cliflag.NamedFlagSets) *AuthenticationConfigOptions {
	return new(AuthenticationConfigOptions).AddFlags(nfs.FlagSet("Authentication Config"))
}

func (o *AuthenticationConfigOptions) AddFlags(fs *pflag.FlagSet) *AuthenticationConfigOptions {
	fs.StringVar(&o.ConfigFile, "authentication-config", o.ConfigFile,
		"Path to a file containing an AuthenticationConfiguration "+
			"(apiserver.config.k8s.io/v1 or v1beta1) enabling multi-issuer OIDC "+
			"authentication. This flag is mutually exclusive with the --oidc-* flags.")
	return o
}

func (o *AuthenticationConfigOptions) Validate() error {
	if o.ConfigFile == "" {
		return nil
	}
	if _, err := os.Stat(o.ConfigFile); err != nil {
		return fmt.Errorf("authentication-config file %q: %w", o.ConfigFile, err)
	}
	return nil
}
