// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/tokenreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy"
)

// KubeOIDCProxyOptions are the proxy's own flags: impersonation, readiness,
// SubjectAccessReview and token passthrough behaviour, trusted proxies and the
// extra headers sent upstream.
type KubeOIDCProxyOptions struct {
	DisableImpersonation bool
	ReadinessProbePort   int

	ReadinessRequireAllIssuers bool

	FlushInterval time.Duration

	MaxImpersonationHeaderValues int

	ExtraHeaders        ExtraHeaderOptions
	SubjectAccessReview SubjectAccessReviewOptions
	TokenPassthrough    TokenPassthroughOptions

	TrustedProxies []string

	AllowedReservedGroups []string
}

// TokenPassthroughOptions configure passing a non-OIDC bearer token through to
// the API server after a TokenReview accepts it.
type TokenPassthroughOptions struct {
	Audiences []string
	Timeout   time.Duration
	Enabled   bool

	// SuccessCacheTTL and FailureCacheTTL bound how long TokenReview results
	// are reused without a fresh API server round trip. Zero disables caching
	// for that result class. Review errors are never cached.
	SuccessCacheTTL time.Duration
	FailureCacheTTL time.Duration
}

// SubjectAccessReviewOptions configure the SubjectAccessReviews that authorize
// a request's impersonation.
type SubjectAccessReviewOptions struct {
	Timeout time.Duration

	// AllowCacheTTL and DenyCacheTTL bound how long a definitive decision is
	// reused without a fresh API server round trip. Zero disables caching for
	// that decision class. Review errors are never cached.
	AllowCacheTTL time.Duration
	DenyCacheTTL  time.Duration
}

// ExtraHeaderOptions configure the extra user headers the proxy adds to every
// impersonated request.
type ExtraHeaderOptions struct {
	ExtraUserHeadersClientIPEnabled bool

	ExtraUserHeaders map[string][]string
}

// NewKubeOIDCProxyOptions registers the Kube-OIDC-Proxy flag set on nfs and
// returns the options it binds.
func NewKubeOIDCProxyOptions(nfs *cliflag.NamedFlagSets) *KubeOIDCProxyOptions {
	return new(KubeOIDCProxyOptions).AddFlags(nfs.FlagSet("Kube-OIDC-Proxy"))
}

// AddFlags binds the proxy flags to fs and returns k for chaining.
func (k *KubeOIDCProxyOptions) AddFlags(fs *pflag.FlagSet) *KubeOIDCProxyOptions {
	fs.BoolVar(&k.DisableImpersonation, "disable-impersonation", k.DisableImpersonation,
		"(Alpha) Forward authenticated requests without impersonation and without "+
			"the proxy's own credentials. Authentication consumes the OIDC bearer token, "+
			"so the request reaches the API server as system:anonymous; any "+
			"Impersonate-* headers the client sent are passed through unchecked, for "+
			"the API server to authorize against that anonymous identity.")

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

	fs.IntVar(&k.MaxImpersonationHeaderValues, "max-impersonation-header-values", subjectaccessreview.DefaultMaxHeaderValues,
		"Maximum total number of impersonation header values accepted per request "+
			"(the Impersonate-User value plus every Impersonate-Group, Impersonate-Uid "+
			"and Impersonate-Extra-* value). Each value costs one SubjectAccessReview "+
			"round trip to the target API server, so this caps the per-request load a "+
			"client can drive. Requests over the cap are rejected with HTTP 431 before "+
			"any SubjectAccessReview is sent. Must be greater than 0.")

	fs.StringSliceVar(&k.TrustedProxies, "trusted-proxies", k.TrustedProxies,
		"Comma-separated list of trusted proxy CIDRs (IPv4 or IPv6, e.g. "+
			"'10.0.0.0/8,192.168.0.0/16'). X-Forwarded-For is honoured to resolve the "+
			"client IP (used for the access log and the Impersonate-Extra-Remote-Client-IP "+
			"header) ONLY when the immediate peer's address falls within one of these "+
			"networks. When empty (the default) no proxy is trusted and the direct peer "+
			"address is always used, so clients cannot spoof their IP via forwarded "+
			"headers. Set this only to the addresses of proxies you operate in front of "+
			"kube-oidc-proxy. Forwarded headers are sanitized to this contract before "+
			"auditing and before the request is forwarded, so audit sourceIPs and the "+
			"upstream API server only see validated values.")

	fs.StringSliceVar(&k.AllowedReservedGroups, "allow-reserved-groups", k.AllowedReservedGroups,
		"Comma-separated list of Kubernetes-reserved ('system:'-prefixed) groups that "+
			"an authentication token is permitted to carry, e.g. "+
			"'system:monitoring'. Every other reserved group is refused with 403, as "+
			"is any reserved username — the proxy holds blanket impersonation rights, "+
			"so a claim naming 'system:masters' or "+
			"'system:serviceaccount:<namespace>:<name>' would otherwise reach those "+
			"privileges. Empty (the default) refuses every reserved group. Each entry "+
			"must itself start with 'system:'. 'system:authenticated' is always "+
			"permitted because the proxy adds it to every request itself, and there is "+
			"no way to permit a reserved username.")

	k.SubjectAccessReview.AddFlags(fs)
	k.TokenPassthrough.AddFlags(fs)
	k.ExtraHeaders.AddFlags(fs)

	return k
}

// AddFlags binds the SubjectAccessReview flags to fs and returns r for
// chaining.
func (r *SubjectAccessReviewOptions) AddFlags(fs *pflag.FlagSet) *SubjectAccessReviewOptions {
	fs.DurationVar(&r.Timeout, "subject-access-review-timeout", subjectaccessreview.DefaultTimeout,
		"Timeout applied when authorizing a request's impersonation via "+
			"SubjectAccessReviews. This is a single shared budget across all SAR "+
			"calls for one request (not per-call), derived from the inbound request "+
			"context so client cancellation still propagates. Must be greater than 0.")

	fs.DurationVar(&r.AllowCacheTTL, "subject-access-review-cache-allow-ttl",
		subjectaccessreview.DefaultAllowCacheTTL,
		"How long an allowed impersonation SubjectAccessReview decision is served "+
			"from an in-memory cache before being re-checked against the API server. "+
			"The tradeoff is revocation lag: revoking a requester's RBAC "+
			"impersonation grant can take up to this long to be enforced while an "+
			"allow decision is cached. The default matches the delegating-"+
			"authorization default in k8s.io/apiserver. Set to 0 to disable caching "+
			"of allowed decisions and re-check every request. Must not be negative. "+
			"Only definitive decisions are cached; API-server errors never are.")

	fs.DurationVar(&r.DenyCacheTTL, "subject-access-review-cache-deny-ttl",
		subjectaccessreview.DefaultDenyCacheTTL,
		"How long a denied impersonation SubjectAccessReview decision is served "+
			"from an in-memory cache before being re-checked against the API server. "+
			"A newly granted RBAC impersonation permission can take up to this long "+
			"to be honoured. The default matches the delegating-authorization "+
			"default in k8s.io/apiserver. Set to 0 to disable caching of denied "+
			"decisions. Must not be negative. Only definitive decisions are cached; "+
			"API-server errors never are.")

	return r
}

// AddFlags binds the token passthrough flags to fs and returns t for chaining.
func (t *TokenPassthroughOptions) AddFlags(fs *pflag.FlagSet) *TokenPassthroughOptions {
	fs.StringSliceVar(&t.Audiences, "token-passthrough-audiences", t.Audiences,
		"(Alpha) List of the identifiers that the resource server presented with the token "+
			"identifies as. The resource server will verify that non OIDC tokens are intended "+
			"for at least one of the audiences in this list. If no audiences are "+
			"provided, the audience will default to the audience of the Kubernetes "+
			"apiserver. Only used when --token-passthrough is also enabled.")

	fs.DurationVar(&t.Timeout, "token-passthrough-request-timeout", tokenreview.DefaultTimeout,
		"Timeout for each TokenReview request the proxy sends to the target API server "+
			"when validating a passthrough token. Only used when --token-passthrough is "+
			"also enabled.")

	fs.DurationVar(&t.SuccessCacheTTL, "token-passthrough-cache-success-ttl", tokenreview.DefaultSuccessCacheTTL,
		"How long a successful TokenReview result is cached and reused without a new "+
			"request to the target API server. A cached success outlives token revocation "+
			"for up to this duration, so keep it low; the default matches the "+
			"kube-apiserver's own delegated-authentication cache (10s). Set to 0 to "+
			"disable caching successful results. Only used when --token-passthrough is "+
			"also enabled.")

	fs.DurationVar(&t.FailureCacheTTL, "token-passthrough-cache-failure-ttl", tokenreview.DefaultFailureCacheTTL,
		"How long an unauthenticated TokenReview result is cached, shielding the "+
			"target API server from repeated reviews of the same invalid token (for "+
			"example during an OIDC issuer outage with --token-passthrough enabled). "+
			"Errors reaching the API server are never cached and are retried on the next "+
			"request. Set to 0 to disable caching unauthenticated results. Only used when "+
			"--token-passthrough is also enabled.")

	fs.BoolVar(&t.Enabled, "token-passthrough", t.Enabled,
		"(Alpha) Requests with Bearer tokens that fail OIDC validation are tried against "+
			"the API server using the Token Review endpoint. If successful, the request "+
			"is sent on as is, with no impersonation.")

	return t
}

// AddFlags binds the extra header flags to fs and returns e for chaining.
func (e *ExtraHeaderOptions) AddFlags(fs *pflag.FlagSet) *ExtraHeaderOptions {
	fs.BoolVar(&e.ExtraUserHeadersClientIPEnabled, "extra-user-header-client-ip",
		e.ExtraUserHeadersClientIPEnabled, "(Alpha) If enabled, proxied requests will "+
			"include the extra user header 'Impersonate-Extra-Remote-Client-IP: "+
			"<CLIENT_IP>' where <CLIENT_IP> is the resolved client IP of the request. "+
			"By default this is the direct peer address; X-Forwarded-For is only "+
			"honoured when the peer is within a --trusted-proxies network.")

	fs.Var(newStringToStringSliceValue(&e.ExtraUserHeaders), "extra-user-headers",
		"(Alpha) A list of key value pairs of extra user headers to pass with "+
			"proxied requests as part of the impersonated request. A single key can "+
			"hold multiple values.")

	return e
}

// Validate checks the proxy flags and returns every problem found, joined.
func (k *KubeOIDCProxyOptions) Validate() error {
	var errs []error

	// Extra user headers are part of the impersonated request, which
	// --disable-impersonation never sends.
	if k.DisableImpersonation {
		if k.ExtraHeaders.ExtraUserHeadersClientIPEnabled {
			errs = append(errs, errors.New("--extra-user-header-client-ip cannot be used with --disable-impersonation"))
		}
		if len(k.ExtraHeaders.ExtraUserHeaders) > 0 {
			errs = append(errs, errors.New("--extra-user-headers cannot be used with --disable-impersonation"))
		}
	}

	// The passthrough flags are checked regardless of --token-passthrough —
	// like --subject-access-review-timeout — so a broken value never lies
	// dormant until the feature is switched on. Zero is meaningful for the
	// cache TTLs (it disables that class of caching); only negatives are
	// configuration mistakes.
	if k.TokenPassthrough.Timeout <= 0 {
		errs = append(errs, fmt.Errorf("--token-passthrough-request-timeout must be greater than 0, got %s", k.TokenPassthrough.Timeout))
	}
	if k.TokenPassthrough.SuccessCacheTTL < 0 {
		errs = append(errs, fmt.Errorf("--token-passthrough-cache-success-ttl must not be negative (0 disables caching of successful results), got %s", k.TokenPassthrough.SuccessCacheTTL))
	}
	if k.TokenPassthrough.FailureCacheTTL < 0 {
		errs = append(errs, fmt.Errorf("--token-passthrough-cache-failure-ttl must not be negative (0 disables caching of unauthenticated results), got %s", k.TokenPassthrough.FailureCacheTTL))
	}

	if k.SubjectAccessReview.Timeout <= 0 {
		errs = append(errs, fmt.Errorf("--subject-access-review-timeout must be greater than 0, got %s", k.SubjectAccessReview.Timeout))
	}

	if k.SubjectAccessReview.AllowCacheTTL < 0 {
		errs = append(errs, fmt.Errorf("--subject-access-review-cache-allow-ttl must not be negative (0 disables caching of allowed decisions), got %s", k.SubjectAccessReview.AllowCacheTTL))
	}

	if k.SubjectAccessReview.DenyCacheTTL < 0 {
		errs = append(errs, fmt.Errorf("--subject-access-review-cache-deny-ttl must not be negative (0 disables caching of denied decisions), got %s", k.SubjectAccessReview.DenyCacheTTL))
	}

	if k.MaxImpersonationHeaderValues <= 0 {
		errs = append(errs, fmt.Errorf("--max-impersonation-header-values must be greater than 0, got %d", k.MaxImpersonationHeaderValues))
	}

	// The proxy's own rules, applied here too so a bad value is reported with
	// the other flag errors rather than only once the proxy is being built.
	if err := proxy.ValidateTrustedProxies(k.TrustedProxies); err != nil {
		errs = append(errs, fmt.Errorf("--trusted-proxies: %w", err))
	}
	if err := proxy.ValidateAllowedReservedGroups(k.AllowedReservedGroups); err != nil {
		errs = append(errs, fmt.Errorf("--allow-reserved-groups: %w", err))
	}

	return errors.Join(errs...)
}
