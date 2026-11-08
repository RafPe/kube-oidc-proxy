// Copyright Jetstack Ltd. See LICENSE for details.

// Package proxy implements the reverse proxy that authenticates requests via
// OIDC and forwards them to the Kubernetes API server using impersonation.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/server"
	apiserveroptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/accesslog"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/hooks"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	utiltoken "github.com/rafpe/kube-oidc-proxy/pkg/util/token"
)

// ReservedIdentityPrefix is the username/group prefix Kubernetes reserves for
// its own identities. checkReservedIdentity refuses to mint one from a token
// claim; the command layer uses it to refuse an operator prefix that would.
const ReservedIdentityPrefix = "system:"

// The token bucket the two client-driven warning records draw from: a steady
// one record per second per reason, room for a burst of ten, and one
// log.warning.suppressed summary a minute reporting what was dropped.
const (
	warnLimiterRate     float64 = 1
	warnLimiterBurst            = 10
	warnLimiterInterval         = time.Minute
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

type errorHandlerFn func(http.ResponseWriter, *http.Request, error)

type Proxy struct {
	oidcRequestAuthenticator *bearertoken.Authenticator
	tokenAuthenticator       authenticator.Token
	tokenReviewer            authenticator.Token
	subjectAccessReviewer    *subjectaccessreview.SubjectAccessReview
	secureServingInfo        *server.SecureServingInfo
	auditor                  *audit.Audit

	restConfig            *rest.Config
	clientTransport       http.RoundTripper
	noAuthClientTransport http.RoundTripper

	config *Config

	// requestLogger is the request-component logger every request-path record
	// is emitted through, and the logger the request filter puts on the
	// request context.
	//
	// oidcLogger, tokenReviewLogger and upstreamLogger are the component
	// loggers for the records registered to those components. The
	// request-scoped logger on the context carries component=request, so it
	// must not be used for them: a record's component is part of its contract,
	// not of where it happens to be emitted from.
	//
	// None of the four is ever nil: New derives all of them from the required
	// root logger, and the tests that build a Proxy by hand set them too.
	requestLogger     *slog.Logger
	oidcLogger        *slog.Logger
	tokenReviewLogger *slog.Logger
	upstreamLogger    *slog.Logger

	// trustedProxies is the parsed form of config.TrustedProxies, resolved once
	// at construction. The request-id and forward-header filters are the only
	// readers; everything after them takes the client IP they resolved.
	trustedProxies []*net.IPNet

	// allowedReservedGroups is the set form of config.AllowedReservedGroups,
	// resolved once at construction so the request path does no allocation.
	allowedReservedGroups sets.Set[string]

	// access writes the one access record per request. Injected rather than a
	// package global so the destination is fixed at construction.
	access *accesslog.AccessLogger

	// warnLimiter token-buckets the only two records a client can produce
	// without bound, request.anomaly.detected and request.headers.dropped, and
	// summarises what it dropped through log.warning.suppressed. The access
	// record is deliberately not limited: a denial is always written. A nil
	// limiter allows everything, so a partially wired Proxy never silences a
	// warning.
	warnLimiter *logging.Limiter

	// metrics is the process recorder every request observation goes to. A
	// nil recorder is a no-op, so a Proxy built without one (every unit test
	// that constructs the struct directly, and a binary run without
	// --metrics-bind-address) records nothing and never nil-checks.
	metrics *metrics.Recorder

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
	// Logger is the process root logger. New derives one component logger per
	// collaborator from it; there is no package-level fallback, so it is
	// required.
	Logger *slog.Logger

	RestConfig         *rest.Config
	TokenAuthenticator authenticator.Token

	// AuditOptions is the apiserver audit configuration the auditor applies.
	// Optional: nil configures no audit backend.
	AuditOptions *apiserveroptions.AuditOptions

	// TokenReviewer authenticates passthrough bearer tokens, typically a
	// tokenreview.TokenReview optionally wrapped by tokenreview.NewCached.
	TokenReviewer         authenticator.Token
	SubjectAccessReviewer *subjectaccessreview.SubjectAccessReview
	SecureServingInfo     *server.SecureServingInfo
	Config                *Config

	// Metrics is the process recorder. Optional: nil records nothing.
	Metrics *metrics.Recorder
}

// New validates deps and constructs a Proxy. Invalid configurations fail here,
// at construction, rather than on the first request.
func New(deps Dependencies) (*Proxy, error) {
	if deps.Logger == nil {
		return nil, errors.New("proxy: Logger is required")
	}
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
	cfg.ExtraUserHeaders = cloneExtra(deps.Config.ExtraUserHeaders)
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

	auditor, err := audit.New(deps.AuditOptions, cfg.ExternalAddress, deps.SecureServingInfo,
		logging.ForComponent(deps.Logger, logging.ComponentAudit))
	if err != nil {
		return nil, err
	}
	auditor.WithMetrics(deps.Metrics)

	// One request-component logger serves both the access record and every
	// other record the request path emits, so they share a destination and a
	// component without a package global.
	requestLogger := logging.ForComponent(deps.Logger, logging.ComponentRequest)

	return &Proxy{
		metrics:                  deps.Metrics,
		restConfig:               deps.RestConfig,
		requestLogger:            requestLogger,
		oidcLogger:               logging.ForComponent(deps.Logger, logging.ComponentOIDC),
		tokenReviewLogger:        logging.ForComponent(deps.Logger, logging.ComponentTokenReview),
		upstreamLogger:           logging.ForComponent(deps.Logger, logging.ComponentUpstream),
		hooks:                    hooks.New(logging.ForComponent(deps.Logger, logging.ComponentShutdown)),
		tokenReviewer:            deps.TokenReviewer,
		subjectAccessReviewer:    deps.SubjectAccessReviewer,
		secureServingInfo:        deps.SecureServingInfo,
		config:                   &cfg,
		trustedProxies:           trustedProxies,
		allowedReservedGroups:    allowedReservedGroups,
		oidcRequestAuthenticator: bearertoken.New(deps.TokenAuthenticator),
		tokenAuthenticator:       deps.TokenAuthenticator,
		auditor:                  auditor,
		access:                   accesslog.NewAccessLogger(requestLogger),
		warnLimiter:              logging.NewLimiter(warnLimiterRate, warnLimiterBurst, warnLimiterInterval, nil),
	}, nil
}

// Run wires up the reverse-proxy handler chain and starts serving until ctx is
// cancelled. It returns a channel that is closed once serving has fully stopped
// and a second channel that is closed once the listener has stopped accepting.
func (p *Proxy) Run(ctx context.Context) (<-chan struct{}, <-chan struct{}, error) {
	clientRT, err := p.roundTripperForRestConfig(p.restConfig)
	if err != nil {
		return nil, nil, err
	}
	p.clientTransport = clientRT

	// A request forwarded without impersonation carries no credentials of the
	// proxy's own: it goes out on a transport built without them.
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

	url, err := url.Parse(p.restConfig.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse url: %w", err)
	}

	p.handleError = p.newErrorHandler()

	proxyHandler := httputil.NewSingleHostReverseProxy(url)
	proxyHandler.Transport = p
	proxyHandler.ErrorHandler = p.handleError
	proxyHandler.FlushInterval = p.config.FlushInterval

	go p.flushWarnLimiter(ctx) //nolint:gosec // G118: the final flush runs after ctx is cancelled and must not be scoped to it.

	waitCh, listenerStoppedCh, err := p.serve(ctx, proxyHandler)
	if err != nil {
		return nil, nil, err
	}

	return waitCh, listenerStoppedCh, nil
}

// flushWarnLimiter reports what the warning limiter dropped, once per interval
// and once more as the proxy stops so a burst suppressed just before shutdown
// is still accounted for.
func (p *Proxy) flushWarnLimiter(ctx context.Context) {
	ticker := time.NewTicker(warnLimiterInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.warnLimiter.Flush(context.Background(), p.requestLogger)
		case <-ctx.Done():
			p.warnLimiter.Flush(context.Background(), p.requestLogger)
			return
		}
	}
}

func (p *Proxy) serve(ctx context.Context, handler http.Handler) (<-chan struct{}, <-chan struct{}, error) {
	handler = p.withHandlers(handler)

	if err := p.auditor.Run(ctx); err != nil {
		return nil, nil, err
	}
	// The backend flushes on shutdown, after the listener has stopped.
	p.hooks.AddPreShutdownHook("AuditBackend", p.auditor.Shutdown)

	// securely serve using serving config. The apiserver's Serve stops on a
	// closed channel, which is what the context's Done channel is.
	waitCh, listenerStoppedCh, err := p.secureServingInfo.Serve(handler, time.Second*60, ctx.Done())
	if err != nil {
		return nil, nil, err
	}

	return waitCh, listenerStoppedCh, nil
}

// RoundTrip is called last and is used to manipulate the forwarded request using context.
func (p *Proxy) RoundTrip(req *http.Request) (*http.Response, error) {
	// Here we have successfully authenticated so now need to determine whether
	// we need use impersonation or not.

	// With impersonation disabled or the token passed through, the request is
	// forwarded as it stands: the passthrough path left the client's bearer
	// token in place, and the disabled path forwards the authenticated request
	// without credentials of its own.
	if reqctx.NoImpersonation(req) {
		p.recordDecision(req, accesslog.Decision{
			Allowed:    true,
			AuthMethod: reqctx.AuthMethod(req),
			Inbound:    userFromContext(req),
		})
		return p.noAuthClientTransport.RoundTrip(req)
	}

	impersonationConf := reqctx.ImpersonationConfig(req)
	if impersonationConf == nil {
		return nil, errNoImpersonationConfig
	}

	rt := transport.NewImpersonatingRoundTripper(*impersonationConf.ImpersonationConfig, p.clientTransport)

	// Record the admitted request. Written before the upstream call so a watch
	// or exec that runs for hours still produces its access record immediately.
	p.recordDecision(req, accesslog.Decision{
		Allowed:    true,
		AuthMethod: reqctx.AuthMethod(req),
		Inbound:    impersonationConf.InboundUser,
		Outbound:   impersonationConf.ImpersonatedUser,
	})

	return rt.RoundTrip(req)
}

func (p *Proxy) reviewToken(req *http.Request) bool {
	ctx := req.Context()

	bearer, found := utiltoken.ParseFromRequest(req)
	if !found {
		logging.Emit(ctx, p.tokenReviewLogger, logging.EventAuthnTokenMissing)
		p.metrics.AuthenticationAttempt(metrics.AuthMethodTokenReview, metrics.AuthRejected)
		return false
	}

	_, ok, err := p.tokenReviewer.AuthenticateToken(ctx, bearer)
	if err != nil {
		// The reviewer could not answer. That is a dependency failure, not a
		// verdict on the token: the caller fails closed.
		logging.Emit(ctx, p.tokenReviewLogger, logging.EventAuthnTokenReviewFailed,
			slog.String("reason", string(metrics.ReasonAuthenticationDependencyError)), logging.ErrAttr(err))
		p.metrics.AuthenticationAttempt(metrics.AuthMethodTokenReview, metrics.AuthError)
		return false
	}

	// The reviewer answered, and it has already recorded the outcome: a live
	// TokenReview emits authn.tokenreview.completed with its duration, a cache
	// hit emits cache.tokenreview.lookup with the cached verdict. A rejection
	// is such an answer, not a failure, so nothing more is recorded here.
	if ok {
		p.metrics.AuthenticationAttempt(metrics.AuthMethodTokenReview, metrics.AuthAccepted)
	} else {
		p.metrics.AuthenticationAttempt(metrics.AuthMethodTokenReview, metrics.AuthRejected)
	}
	return ok
}

// recordDecision writes the one access record a request produces and counts
// it. Every decision goes through here, so the metric and the record can
// never disagree about what was decided.
func (p *Proxy) recordDecision(req *http.Request, d accesslog.Decision) {
	p.access.LogDecision(req, d)
	p.metrics.AccessDecision(d.AuthMethod, d.Allowed, d.Reason)
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
