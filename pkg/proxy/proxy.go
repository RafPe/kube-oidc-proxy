// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"k8s.io/klog/v2"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/hooks"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/tokenreview"
)

const (
	UserHeaderClientIPKey = "Remote-Client-IP"
	timestampLayout       = "2006-01-02T15:04:05-0700"
)

var (
	errUnauthorized          = errors.New("unauthorized")
	errNoName                = errors.New("no name in OIDC info")
	errNoImpersonationConfig = errors.New("no impersonation configuration in context")
)

type Config struct {
	DisableImpersonation bool
	TokenReview          bool

	FlushInterval   time.Duration
	ExternalAddress string

	ExtraUserHeaders                map[string][]string
	ExtraUserHeadersClientIPEnabled bool
}

type errorHandlerFn func(http.ResponseWriter, *http.Request, error)

type Proxy struct {
	oidcRequestAuther     *bearertoken.Authenticator
	tokenAuthenticator    authenticator.Token
	tokenReviewer         *tokenreview.TokenReview
	subjectAccessReviewer *subjectaccessreview.SubjectAccessReview
	secureServingInfo     *server.SecureServingInfo
	auditor               *audit.Audit

	restConfig            *rest.Config
	clientTransport       http.RoundTripper
	noAuthClientTransport http.RoundTripper

	config *Config

	hooks       *hooks.Hooks
	handleError errorHandlerFn
}

// Dependencies bundles the collaborators a Proxy needs. Using a named struct
// keeps call sites self-documenting and lets New validate required
// dependencies up front rather than failing on the first request.
//
// Ownership: New takes ownership of the Config value (it copies it, including
// the ExtraUserHeaders map, so later mutation of the caller's Config does not
// change proxy behavior). The remaining pointers are collaborators the Proxy
// borrows for its lifetime; it does not close or mutate them. The Proxy creates
// and owns its auditor and shutdown hooks internally.
type Dependencies struct {
	RestConfig            *rest.Config
	TokenAuthenticator    authenticator.Token
	AuditOptions          *options.AuditOptions
	TokenReviewer         *tokenreview.TokenReview
	SubjectAccessReviewer *subjectaccessreview.SubjectAccessReview
	SecureServingInfo     *server.SecureServingInfo
	Config                *Config
}

// New validates deps and constructs a Proxy. Invalid configurations fail here,
// at construction, rather than on the first request.
func New(deps Dependencies) (*Proxy, error) {
	if deps.RestConfig == nil {
		return nil, errors.New("proxy: RestConfig is required")
	}
	if deps.TokenAuthenticator == nil {
		return nil, errors.New("proxy: TokenAuthenticator is required")
	}
	if deps.SubjectAccessReviewer == nil {
		return nil, errors.New("proxy: SubjectAccessReviewer is required")
	}
	if deps.SecureServingInfo == nil {
		return nil, errors.New("proxy: SecureServingInfo is required")
	}
	if deps.Config == nil {
		return nil, errors.New("proxy: Config is required")
	}
	// Reject inconsistent combinations: token-review handling has no reviewer to
	// call, so enabling it without one can never work.
	if deps.Config.TokenReview && deps.TokenReviewer == nil {
		return nil, errors.New("proxy: TokenReview enabled but no TokenReviewer provided")
	}

	// Copy the Config and its mutable map at the construction boundary so that
	// mutating the caller's Config (or the map it shares) after New cannot alter
	// proxy behavior.
	cfg := *deps.Config
	cfg.ExtraUserHeaders = cloneHeaderMap(deps.Config.ExtraUserHeaders)

	auditor, err := audit.New(deps.AuditOptions, cfg.ExternalAddress, deps.SecureServingInfo)
	if err != nil {
		return nil, err
	}

	return &Proxy{
		restConfig:            deps.RestConfig,
		hooks:                 hooks.New(),
		tokenReviewer:         deps.TokenReviewer,
		subjectAccessReviewer: deps.SubjectAccessReviewer,
		secureServingInfo:     deps.SecureServingInfo,
		config:                &cfg,
		oidcRequestAuther:     bearertoken.New(deps.TokenAuthenticator),
		tokenAuthenticator:    deps.TokenAuthenticator,
		auditor:               auditor,
	}, nil
}

// cloneHeaderMap returns a deep copy of a header map so the Proxy never shares
// mutable state with its caller. A nil input yields nil.
func cloneHeaderMap(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, vs := range in {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func (p *Proxy) Run(stopCh <-chan struct{}) (<-chan struct{}, <-chan struct{}, error) {
	// standard round tripper for proxy to API Server
	clientRT, err := p.roundTripperForRestConfig(p.restConfig)
	if err != nil {
		return nil, nil, err
	}
	p.clientTransport = clientRT

	// No auth round tripper for no impersonation
	if p.config.DisableImpersonation || p.config.TokenReview {
		noAuthClientRT, err := p.roundTripperForRestConfig(&rest.Config{
			APIPath: p.restConfig.APIPath,
			Host:    p.restConfig.Host,
			Timeout: p.restConfig.Timeout,
			TLSClientConfig: rest.TLSClientConfig{
				CAFile: p.restConfig.CAFile,
				CAData: p.restConfig.CAData,
			},
		})
		if err != nil {
			return nil, nil, err
		}

		p.noAuthClientTransport = noAuthClientRT
	}

	// get API server url
	url, err := url.Parse(p.restConfig.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse url: %s", err)
	}

	p.handleError = p.newErrorHandler()

	// Set up proxy handler using proxy
	proxyHandler := httputil.NewSingleHostReverseProxy(url)
	proxyHandler.Transport = p
	proxyHandler.ErrorHandler = p.handleError
	proxyHandler.FlushInterval = p.config.FlushInterval

	waitCh, listenerStoppedCh, err := p.serve(proxyHandler, stopCh)
	if err != nil {
		return nil, nil, err
	}

	return waitCh, listenerStoppedCh, nil
}

func (p *Proxy) serve(handler http.Handler, stopCh <-chan struct{}) (<-chan struct{}, <-chan struct{}, error) {
	// Setup proxy handlers
	handler = p.withHandlers(handler)

	// Run auditor
	if err := p.auditor.Run(stopCh); err != nil {
		return nil, nil, err
	}

	// securely serve using serving config
	waitCh, listenerStoppedCh, err := p.secureServingInfo.Serve(handler, time.Second*60, stopCh)
	if err != nil {
		return nil, nil, err
	}

	return waitCh, listenerStoppedCh, nil
}

// RoundTrip is called last and is used to manipulate the forwarded request using context.
func (p *Proxy) RoundTrip(req *http.Request) (*http.Response, error) {
	// Here we have successfully authenticated so now need to determine whether
	// we need use impersonation or not.

	// If no impersonation then we return here without setting impersonation
	// header but re-introduce the token we removed.
	if context.NoImpersonation(req) {
		token := context.BearerToken(req)
		req.Header.Add("Authorization", token)
		return p.noAuthClientTransport.RoundTrip(req)
	}

	// Get the impersonation headers from the context.
	impersonationConf := context.ImpersonationConfig(req)
	if impersonationConf == nil {
		return nil, errNoImpersonationConfig
	}

	// Set up impersonation request.
	rt := transport.NewImpersonatingRoundTripper(*impersonationConf.ImpersonationConfig, p.clientTransport)

	// Log the request
	logging.LogSuccessfulRequest(req, *impersonationConf.InboundUser, *impersonationConf.ImpersonatedUser)

	// Push request through round trippers to the API server.
	return rt.RoundTrip(req)
}

func (p *Proxy) reviewToken(rw http.ResponseWriter, req *http.Request) bool {
	var remoteAddr string
	req, remoteAddr = context.RemoteAddr(req)

	klog.V(4).Infof("attempting to validate a token in request using TokenReview endpoint(%s)",
		remoteAddr)

	ok, err := p.tokenReviewer.Review(req)
	if err != nil {
		klog.Errorf("unable to authenticate the request via TokenReview due to an error (%s): %s",
			remoteAddr, err)
		return false
	}

	if !ok {
		klog.V(4).Infof("passing request with valid token through (%s)",
			remoteAddr)

		return false
	}

	// No error and ok so passthrough the request
	return true
}

func (p *Proxy) roundTripperForRestConfig(config *rest.Config) (http.RoundTripper, error) {
	// get golang tls config to the API server
	tlsConfig, err := rest.TLSConfigFor(config)
	if err != nil {
		return nil, err
	}

	// create tls transport to request
	tlsTransport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}

	// get kube transport config form rest client config
	restTransportConfig, err := config.TransportConfig()
	if err != nil {
		return nil, err
	}

	// wrap golang tls config with kube transport round tripper
	clientRT, err := transport.HTTPWrappersForConfig(restTransportConfig, tlsTransport)
	if err != nil {
		return nil, err
	}

	return clientRT, nil
}

// Return the proxy OIDC token authenticator
func (p *Proxy) OIDCTokenAuthenticator() authenticator.Token {
	return p.tokenAuthenticator
}

func (p *Proxy) RunPreShutdownHooks() error {
	return p.hooks.RunPreShutdownHooks()
}
