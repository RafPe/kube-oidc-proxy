// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"net"

	apiserveroptions "k8s.io/apiserver/pkg/server/options"
	cliflag "k8s.io/component-base/cli/flag"
)

// newSecureServingOptions binds the apiserver's own serving flags under the
// Secure Serving flag set, with the proxy's defaults: all interfaces, port
// 6443, a certificate pair named after the binary. The proxy adds nothing else
// to them, so it holds the apiserver type directly.
func newSecureServingOptions(nfs *cliflag.NamedFlagSets) *apiserveroptions.SecureServingOptions {
	s := &apiserveroptions.SecureServingOptions{
		BindAddress: net.ParseIP("0.0.0.0"),
		BindPort:    6443,
		Required:    true,
		ServerCert: apiserveroptions.GeneratableKeyCert{
			PairName:      AppName,
			CertDirectory: "/var/run/kubernetes",
		},
	}
	s.AddFlags(nfs.FlagSet("Secure Serving"))
	return s
}
