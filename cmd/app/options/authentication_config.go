// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
	"sigs.k8s.io/yaml"

	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
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
		"Path to a file containing an AuthenticationConfiguration (apiserver.config.k8s.io/v1beta1). "+
			"This flag is mutually exclusive with the --oidc-* flags.")
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

func (o *AuthenticationConfigOptions) Load() (*apiserverv1beta1.AuthenticationConfiguration, error) {
	data, err := os.ReadFile(o.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("reading authentication-config %q: %w", o.ConfigFile, err)
	}
	var cfg apiserverv1beta1.AuthenticationConfiguration
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing authentication-config %q: %w", o.ConfigFile, err)
	}
	if len(cfg.JWT) == 0 {
		return nil, fmt.Errorf("authentication-config %q: jwt list must not be empty", o.ConfigFile)
	}
	return &cfg, nil
}
