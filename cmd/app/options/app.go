// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"time"

	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/util/flags"
)

type KubeOIDCProxyOptions struct {
	DisableImpersonation bool
	ReadinessProbePort   int

	ReadinessRequireAllIssuers bool

	FlushInterval time.Duration

	SubjectAccessReviewTimeout time.Duration

	ExtraHeaderOptions ExtraHeaderOptions
	TokenPassthrough   TokenPassthroughOptions

	TrustedProxies []string

	AllowReservedIdentityClaims bool
}

type TokenPassthroughOptions struct {
	Audiences []string
	Enabled   bool
}

type ExtraHeaderOptions struct {
	EnableClientIPExtraUserHeader bool

	ExtraUserHeaders map[string][]string
}

func NewKubeOIDCProxyOptions(nfs *cliflag.NamedFlagSets) *KubeOIDCProxyOptions {
	return new(KubeOIDCProxyOptions).AddFlags(nfs.FlagSet("Kube-OIDC-Proxy"))
}

func (k *KubeOIDCProxyOptions) AddFlags(fs *pflag.FlagSet) *KubeOIDCProxyOptions {
	fs.BoolVar(&k.DisableImpersonation, "disable-impersonation", k.DisableImpersonation,
		"(Alpha) Disable the impersonation of authenticated requests. All "+
			"authenticated requests will be forwarded as is.")

	fs.IntVarP(&k.ReadinessProbePort, "readiness-probe-port", "P", 8080,
		"Port to expose readiness probe.")

	fs.BoolVar(&k.ReadinessRequireAllIssuers, "readiness-require-all-issuers", false,
		"If true, the readiness probe reports ready only once every issuer in the "+
			"authentication configuration has been initialized (JWKS fetched). If false "+
			"(default), the proxy reports ready as soon as at least one issuer is "+
			"initialized; issuers still pending are logged and keep initializing in "+
			"the background. Configuration errors always fail startup regardless.")

	fs.DurationVar(&k.FlushInterval, "flush-interval", time.Millisecond*50,
		"Specifies the interval to flush request bodies. If 0ms, "+
			"no periodic flushing is done. A negative value means to flush "+
			"immediately after each write. Streaming requests such as 'kubectl exec' "+
			"will ignore this option and flush immediately.")

	fs.DurationVar(&k.SubjectAccessReviewTimeout, "subject-access-review-timeout", subjectaccessreview.DefaultTimeout,
		"Timeout applied when authorizing a request's impersonation via "+
			"SubjectAccessReviews. This is a single shared budget across all SAR "+
			"calls for one request (not per-call), derived from the inbound request "+
			"context so client cancellation still propagates. Must be greater than 0.")

	fs.StringSliceVar(&k.TrustedProxies, "trusted-proxies", k.TrustedProxies,
		"Comma-separated list of trusted proxy CIDRs (IPv4 or IPv6, e.g. "+
			"'10.0.0.0/8,192.168.0.0/16'). X-Forwarded-For is honoured to resolve the "+
			"client IP (used for the access log and the Impersonate-Extra-Remote-Client-IP "+
			"header) ONLY when the immediate peer's address falls within one of these "+
			"networks. When empty (the default) no proxy is trusted and the direct peer "+
			"address is always used, so clients cannot spoof their IP via forwarded "+
			"headers. Set this only to the addresses of proxies you operate in front of "+
			"kube-oidc-proxy.")

	fs.BoolVar(&k.AllowReservedIdentityClaims, "allow-reserved-identity-claims", false,
		"If true, an authentication token may mint identities carrying the "+
			"Kubernetes-reserved 'system:' prefix — including the cluster-admin group "+
			"'system:masters' and any service account "+
			"('system:serviceaccount:<namespace>:<name>') as a username. The proxy is "+
			"granted blanket impersonation rights, so enabling this makes the OIDC "+
			"issuer's claims a path to those privileges. By default (false) such an "+
			"identity is refused with 403; 'system:authenticated' remains permitted as "+
			"a group because the proxy adds it to every request itself.")

	k.TokenPassthrough.AddFlags(fs)
	k.ExtraHeaderOptions.AddFlags(fs)

	return k
}

func (t *TokenPassthroughOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringSliceVar(&t.Audiences, "token-passthrough-audiences", t.Audiences, ""+
		"(Alpha) List of the identifiers that the resource server presented with the token "+
		"identifies as. The resource server will verify that non OIDC tokens are intended "+
		"for at least one of the audiences in this list. If no audiences are "+
		"provided, the audience will default to the audience of the Kubernetes "+
		"apiserver. Only used when --token-passthrough is also enabled.")

	fs.BoolVar(&t.Enabled, "token-passthrough", t.Enabled, ""+
		"(Alpha) Requests with Bearer tokens that fail OIDC validation are tried against "+
		"the API server using the Token Review endpoint. If successful, the request "+
		"is sent on as is, with no impersonation.")
}

func (e *ExtraHeaderOptions) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&e.EnableClientIPExtraUserHeader, "extra-user-header-client-ip",
		e.EnableClientIPExtraUserHeader, "(Alpha) If enabled, proxied requests will "+
			"include the extra user header 'Impersonate-Extra-Remote-Client-IP: "+
			"<CLIENT_IP>' where <CLIENT_IP> is the resolved client IP of the request. "+
			"By default this is the direct peer address; X-Forwarded-For is only "+
			"honoured when the peer is within a --trusted-proxies network.")

	fs.Var(flags.NewStringToStringSliceValue(&e.ExtraUserHeaders), "extra-user-headers",
		"(Alpha) A list of key value pairs of extra user headers to pass with "+
			"proxied requests as part of the impersonated request. A single key can "+
			"hold multiple values.")
}
