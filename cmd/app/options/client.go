// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	cliflag "k8s.io/component-base/cli/flag"
)

// ClientOptions configures the client the proxy uses to reach the API server
// for its own calls (TokenReview, SubjectAccessReview and the reverse proxy
// itself). The connection flags are client-go's own kubeconfig override flags,
// bound directly, so the proxy carries no dependency on the kubectl runtime.
type ClientOptions struct {
	// Kubeconfig is the path of the kubeconfig to load. Empty means the
	// in-cluster configuration unless another client flag selects otherwise.
	Kubeconfig string

	KubeClientQPS   float32
	KubeClientBurst int

	// overrides holds the --server, --token, --context and friends that
	// override whatever the kubeconfig says.
	overrides clientcmd.ConfigOverrides
}

func NewClientOptions(nfs *cliflag.NamedFlagSets) *ClientOptions {
	return new(ClientOptions).AddFlags(nfs.FlagSet("Client"))
}

func (c *ClientOptions) AddFlags(fs *pflag.FlagSet) *ClientOptions {
	fs.StringVar(&c.Kubeconfig, "kubeconfig", c.Kubeconfig,
		"Path to the kubeconfig file to use for requests to the API server.")

	// Impersonation is the proxy's own job: an --as flag here would make the
	// proxy impersonate that identity on every call of its own, so the three
	// impersonation overrides are not offered.
	names := clientcmd.RecommendedConfigOverrideFlags("")
	names.AuthOverrideFlags.Impersonate.LongName = ""
	names.AuthOverrideFlags.ImpersonateUID.LongName = ""
	names.AuthOverrideFlags.ImpersonateGroups.LongName = ""
	clientcmd.BindOverrideFlags(&c.overrides, fs, names)

	fs.Float32Var(&c.KubeClientQPS, "kube-client-qps", c.KubeClientQPS, "Sets the QPS on the app "+
		"kubernetes client, this will configure throttling on requests sent to the apiserver "+
		"(If not set, it will use client default ones)")
	fs.IntVar(&c.KubeClientBurst, "kube-client-burst", c.KubeClientBurst, "Sets the burst on the app "+
		"kubernetes client, this will configure throttling on requests sent to the apiserver"+
		"(If not set, it will use client default ones)")

	return c
}

// ToRESTConfig builds the client configuration from the kubeconfig and the
// overrides given on the command line.
func (c *ClientOptions) ToRESTConfig() (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = c.Kubeconfig
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &c.overrides).ClientConfig()
}

// ClientFlagsChanged reports whether any connection flag was given, which is
// what selects the kubeconfig path over the in-cluster configuration.
func (c *ClientOptions) ClientFlagsChanged(cmd *cobra.Command) bool {
	for _, f := range clientOptionFlags() {
		if ff := cmd.Flag(f); ff != nil && ff.Changed {
			return true
		}
	}

	return false
}

func clientOptionFlags() []string {
	return []string{"certificate-authority", "client-certificate", "client-key", "cluster",
		"context", "insecure-skip-tls-verify", "kubeconfig", "namespace",
		"request-timeout", "server", "token", "user",
	}
}
