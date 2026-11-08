// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"net"

	"github.com/spf13/pflag"
	apiserveroptions "k8s.io/apiserver/pkg/server/options"
	cliflag "k8s.io/component-base/cli/flag"
)

// SecureServingOptions are the apiserver's serving flags with the proxy's
// defaults: all interfaces, port 6443, a certificate pair named after the
// binary.
type SecureServingOptions struct {
	*apiserveroptions.SecureServingOptions
}

// NewSecureServingOptions registers the Secure Serving flag set on nfs and
// returns the options it binds.
func NewSecureServingOptions(nfs *cliflag.NamedFlagSets) *SecureServingOptions {
	s := &SecureServingOptions{
		SecureServingOptions: &apiserveroptions.SecureServingOptions{
			BindAddress: net.ParseIP("0.0.0.0"),
			BindPort:    6443,
			Required:    true,
			ServerCert: apiserveroptions.GeneratableKeyCert{
				PairName:      AppName,
				CertDirectory: "/var/run/kubernetes",
			},
		},
	}

	return s.AddFlags(nfs.FlagSet("Secure Serving"))
}

// AddFlags binds the serving flags to fs and returns s for chaining.
func (s *SecureServingOptions) AddFlags(fs *pflag.FlagSet) *SecureServingOptions {
	s.SecureServingOptions.AddFlags(fs)
	return s
}
