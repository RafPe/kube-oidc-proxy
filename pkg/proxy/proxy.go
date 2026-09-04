// Copyright Jetstack Ltd. See LICENSE for details.

// Package proxy implements the reverse proxy that authenticates requests via
// OIDC and forwards them to the Kubernetes API server using impersonation.
package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"k8s.io/klog/v2"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/hooks"
	accesslogging "github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	utiltoken "github.com/rafpe/kube-oidc-proxy/pkg/util/token"
)

const (
	UserHeaderClientIPKey = "Remote-Client-IP"
	timestampLayout       = "2006-01-02T15:04:05-0700"
)

var (
	errUnauthorized          = errors.New("unauthorized")
	errNoName                = errors.New("no name in OIDC info")
	errNoImpersonationConfig = errors.New("no impersonation configuration in context")

	// errReservedIdentity classifies an authenticated identity whose username or
	// groups carry the Kubernetes-reserved "system:" prefix. Such an identity may
	// never originate from a token claim; see checkReservedIdentity.
	errReservedIdentity = errors.New("reserved identity in authentication token")
)

type Config struct {
	DisableImpersonation bool
	TokenReview          bool

	// AllowedReservedGroups names "system:"-prefixed groups the operator has
	// explicitly permitted from a token claim. Empty (the default) refuses every
	// reserved group. Reserved usernames are always refused; see
	// checkReservedIdentity for why the guard exists.
	AllowedReservedGroups []string

	FlushInterval   time.Duration
	ExternalAddress string

	ExtraUserHeaders                map[string][]string
	ExtraUserHeadersClientIPEnabled bool

	// TrustedProxies is the list of CIDRs (IPv4 or IPv6) whose immediate peers
	// are trusted to set X-Forwarded-For. It is validated and parsed at
	// construction. Empty (the default) trusts no proxy, so the direct peer is
	// always used as the client IP and forwarded headers cannot be spoofed.
	TrustedProxies []string
}

type errorHandlerFn func(http.ResponseWriter, *http.Request, error)

type Proxy struct {
	oidcRequestAuther     *bearertoken.Authenticator
	tokenAuthenticator    authenticator.Token
	tokenReviewer         authenticator.Token
	subjectAccessReviewer *subjectaccessreview.SubjectAccessReview
	secureServingInfo     *server.SecureServingInfo
	auditor               *audit.Audit

	restConfig            *rest.Config
	clientTransport       http.RoundTripper
	noAuthClientTransport http.RoundTripper

	config *Config

	// trustedProxies is the parsed form of config.TrustedProxies, resolved once
	// at construction and applied to the client-IP resolvers when Run starts.
	trustedProxies []*net.IPNet

	// allowedReservedGroups is the set form of config.AllowedReservedGroups,
	// resolved once at construction so the request path does no allocation.
	allowedReservedGroups sets.Set[string]

	// access writes the one access record per request. Injected rather than a
	// package global so the destination and the trusted-proxy networks are
	// fixed at construction.
	access *accesslogging.AccessLogger

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
	RestConfig         *rest.Config
	TokenAuthenticator authenticator.Token
	AuditOptions       *options.AuditOptions

	// TokenReviewer authenticates passthrough bearer tokens, typically a
	// tokenreview.TokenReview optionally wrapped by tokenreview.NewCached.
	TokenReviewer         authenticator.Token
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
	cfg.TrustedProxies = append([]string(nil), deps.Config.TrustedProxies...)
	cfg.AllowedReservedGroups = append([]string(nil), deps.Config.AllowedReservedGroups...)

	// Validate trusted-proxy CIDRs up front so a bad configuration fails at
	// construction rather than silently trusting nothing at request time.
	trustedProxies, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}

	// Validate the reserved-group allowlist up front: an entry that is not
	// reserved is a no-op the operator almost certainly did not intend.
	allowedReservedGroups, err := parseAllowedReservedGroups(cfg.AllowedReservedGroups)
	if err != nil {
		return nil, err
	}

	auditor, err := audit.New(deps.AuditOptions, cfg.ExternalAddress, deps.SecureServingInfo)
	if err != nil {
		return nil, err
	}

	// The access record goes to the JSON stream on stdout, as it always has.
	// The root logger becomes an injected dependency in a later change; the
	// destination and the record shape do not change with it.
	root, err := logging.New(logging.Options{})
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
		trustedProxies:        trustedProxies,
		allowedReservedGroups: allowedReservedGroups,
		oidcRequestAuther:     bearertoken.New(deps.TokenAuthenticator),
		tokenAuthenticator:    deps.TokenAuthenticator,
		auditor:               auditor,
		access:                accesslogging.NewAccessLogger(logging.ForComponent(root, logging.ComponentRequest), trustedProxies),
	}, nil
}

// parseAllowedReservedGroups turns the configured allowlist into a set. Every
// entry must itself carry the reserved prefix: allowing a group that was never
// going to be refused is a no-op, and silently accepting it would hide a typo
// in a security-relevant setting. system:authenticated is rejected as an entry
// because the guard always permits it.
func parseAllowedReservedGroups(groups []string) (sets.Set[string], error) {
	if len(groups) == 0 {
		return nil, nil
	}

	allowed := sets.New[string]()
	for _, group := range groups {
		switch {
		case strings.TrimSpace(group) == "":
			return nil, fmt.Errorf("allowed reserved group must not be empty")
		case !strings.HasPrefix(group, reservedIdentityPrefix):
			return nil, fmt.Errorf("allowed reserved group %q does not carry the reserved %q prefix, so listing it has no effect",
				group, reservedIdentityPrefix)
		}
		allowed.Insert(group)
	}

	return allowed, nil
}

// parseTrustedProxies parses a list of CIDR strings (IPv4 or IPv6) into
// networks. Empty or whitespace-only entries are rejected so a malformed flag
// value cannot be silently ignored. A nil/empty input yields a nil slice,
// meaning no proxy is trusted.
func parseTrustedProxies(cidrs []string) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			return nil, fmt.Errorf("proxy: empty trusted-proxy CIDR")
		}
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("proxy: invalid trusted-proxy CIDR %q: %w", c, err)
		}
		nets = append(nets, network)
	}
	return nets, nil
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

// Run wires up the reverse-proxy handler chain and starts serving until stopCh
// is closed. It returns a channel that is closed once serving has fully stopped
// and a second channel that is closed once the listener has stopped accepting.
func (p *Proxy) Run(stopCh <-chan struct{}) (<-chan struct{}, <-chan struct{}, error) {
	// Apply the trusted-proxy networks to the context resolver so the audit
	// log's src_ip and the Remote-Client-IP impersonation extra resolve
	// identically to the access record, which took the same networks at
	// construction. Done here (rather than in New) to keep the package-global
	// setter out of construction-time unit tests.
	context.SetTrustedProxies(p.trustedProxies)

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
		return nil, nil, fmt.Errorf("failed to parse url: %w", err)
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
		p.access.LogDecision(req, accesslogging.Decision{
			Allowed:    true,
			AuthMethod: authMethodFrom(req),
			Inbound:    userFromContext(req),
		})
		return p.noAuthClientTransport.RoundTrip(req)
	}

	// Get the impersonation headers from the context.
	impersonationConf := context.ImpersonationConfig(req)
	if impersonationConf == nil {
		return nil, errNoImpersonationConfig
	}

	// Set up impersonation request.
	rt := transport.NewImpersonatingRoundTripper(*impersonationConf.ImpersonationConfig, p.clientTransport)

	// Record the admitted request. Written before the upstream call so a watch
	// or exec that runs for hours still produces its access record immediately.
	p.access.LogDecision(req, accesslogging.Decision{
		Allowed:    true,
		AuthMethod: authMethodFrom(req),
		Inbound:    *impersonationConf.InboundUser,
		Outbound:   *impersonationConf.ImpersonatedUser,
	})

	// Push request through round trippers to the API server.
	return rt.RoundTrip(req)
}

func (p *Proxy) reviewToken(rw http.ResponseWriter, req *http.Request) bool {
	var remoteAddr string
	req, remoteAddr = context.RemoteAddr(req)

	klog.V(4).Infof("attempting to validate a token in request using TokenReview endpoint(%s)",
		remoteAddr)

	bearer, found := utiltoken.ParseFromRequest(req)
	if !found {
		klog.V(4).Infof("no bearer token in request for TokenReview (%s)", remoteAddr)
		return false
	}

	_, ok, err := p.tokenReviewer.AuthenticateToken(req.Context(), bearer)
	if err != nil {
		klog.Errorf("unable to authenticate the request via TokenReview due to an error (%s): %s",
			remoteAddr, err)
		return false
	}

	if !ok {
		klog.V(4).Infof("token rejected by TokenReview (%s)", remoteAddr)

		return false
	}

	// No error and ok so passthrough the request
	return true
}

func (p *Proxy) roundTripperForRestConfig(config *rest.Config) (http.RoundTripper, error) {
	// client-go's transport reloads file-backed client certificates and closes
	// connections that still use the previous certificate. Restrict ALPN to
	// HTTP/1.1 because Kubernetes streaming requests upgrade to SPDY.
	configCopy := rest.CopyConfig(config)
	configCopy.NextProtos = []string{"http/1.1"}
	clientRT, err := rest.TransportFor(configCopy)
	if err != nil {
		return nil, fmt.Errorf("building API server transport: %w", err)
	}

	return clientRT, nil
}

// OIDCTokenAuthenticator returns the proxy's OIDC token authenticator.
func (p *Proxy) OIDCTokenAuthenticator() authenticator.Token {
	return p.tokenAuthenticator
}

// RunPreShutdownHooks runs the registered pre-shutdown hooks (currently the
// audit backend flush) and returns an aggregate of any failures. It should be
// called once during graceful shutdown.
func (p *Proxy) RunPreShutdownHooks() error {
	return p.hooks.RunPreShutdownHooks()
}
