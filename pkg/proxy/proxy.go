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
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/accesslog"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
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

type Proxy struct {
	oidcRequestAuthenticator *bearertoken.Authenticator
	tokenReviewer            authenticator.Token
	subjectAccessReviewer    *subjectaccessreview.Authorizer
	secureServingInfo        *server.SecureServingInfo
	auditor                  *audit.Audit

	restConfig            *rest.Config
	clientTransport       http.RoundTripper
	noAuthClientTransport http.RoundTripper

	config *Config

	// requestLogger is the request-component logger every request-path record
	// is emitted through, the access record included.
	//
	// oidcLogger, tokenReviewLogger and upstreamLogger are the component
	// loggers for the records registered to those components. requestLogger
	// carries component=request, so it must not be used for them: a record's
	// component is part of its contract, not of where it happens to be emitted
	// from.
	//
	// None of the four is ever nil: New derives all of them from the required
	// root logger.
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

	// warnLimiter token-buckets the only two records a client can produce
	// without bound, request.anomaly.detected and request.headers.dropped, and
	// summarises what it dropped through log.warning.suppressed. The access
	// record is deliberately not limited: a denial is always written.
	warnLimiter *logging.Limiter

	// metrics is the process recorder every request observation goes to. It
	// is optional: a nil recorder is a no-op, so a binary run without
	// --metrics-bind-address records nothing and never nil-checks.
	metrics *metrics.Recorder

	// stopped and listenerStopped are closed once serving has fully stopped
	// and once the listener has stopped accepting; Start sets them and Wait
	// blocks on them.
	stopped, listenerStopped <-chan struct{}
}

// Dependencies bundles the collaborators a Proxy needs. Using a named struct
// keeps call sites self-documenting and lets New validate required
// dependencies up front rather than failing on the first request.
//
// Ownership: New takes ownership of the Config value (it copies it, including
// the ExtraUserHeaders map, so later mutation of the caller's Config does not
// change proxy behavior). The remaining pointers are collaborators the Proxy
// borrows for its lifetime; it does not close or mutate them. That includes the
// auditor: the proxy only wraps requests in its audit chains, while the caller
// starts the backend before Start and flushes it once the proxy has stopped
// serving.
type Dependencies struct {
	// Logger is the process root logger. New derives the request, oidc,
	// tokenreview and upstream component loggers from it, so it takes the root
	// rather than any one of them. Required: New panics on nil.
	Logger *slog.Logger

	RestConfig *rest.Config

	// OIDCTokenAuthenticator verifies the bearer tokens issued by the
	// configured OIDC issuers.
	OIDCTokenAuthenticator authenticator.Token

	// Auditor records the audit events of every request the proxy handles,
	// refused ones included, and supplies the request resolution and
	// long-running rule the whole chain shares (see package audit). Required;
	// an auditor built from nil options configures no backend but keeps every
	// audit filter in the chain.
	Auditor *audit.Audit

	// TokenReviewer authenticates passthrough bearer tokens, typically the
	// authenticator tokenreview.New returns, which applies the result cache
	// its Config asks for. A review that could not be answered must return an
	// error wrapping tokenreview.ErrCreateTokenReview: that is what refuses
	// the request as a dependency failure (401, reason
	// authentication_dependency_error). Any other error is the proxy's own
	// failure and answers 500.
	TokenReviewer         authenticator.Token
	SubjectAccessReviewer *subjectaccessreview.Authorizer
	SecureServingInfo     *server.SecureServingInfo
	Config                *Config

	// Metrics is the process recorder. Optional: nil records nothing.
	Metrics *metrics.Recorder
}

// New validates deps and constructs a Proxy. Invalid configurations fail here,
// at construction, rather than on the first request. A nil Logger is a wiring
// bug rather than a configuration error, so it panics.
func New(deps Dependencies) (*Proxy, error) {
	if deps.Logger == nil {
		panic("proxy: New called with a nil Logger")
	}
	if deps.RestConfig == nil {
		return nil, errors.New("proxy: RestConfig is required")
	}
	if deps.OIDCTokenAuthenticator == nil {
		return nil, errors.New("proxy: OIDCTokenAuthenticator is required")
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
	if deps.Auditor == nil {
		return nil, errors.New("proxy: Auditor is required")
	}
	// Reject inconsistent combinations: token-review handling has no reviewer to
	// call, so enabling it without one can never work.
	if deps.Config.TokenPassthrough && deps.TokenReviewer == nil {
		return nil, errors.New("proxy: TokenPassthrough enabled but no TokenReviewer provided")
	}

	// Copy the Config and its mutable map at the construction boundary so that
	// mutating the caller's Config (or the map it shares) after New cannot alter
	// proxy behavior. The two slices need no copy: they are read only here, and
	// parsed into values of the Proxy's own.
	cfg := *deps.Config
	cfg.ExtraUserHeaders = cloneExtra(deps.Config.ExtraUserHeaders)

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

	clientTransport, err := roundTripperForRestConfig(deps.RestConfig)
	if err != nil {
		return nil, err
	}
	// A request forwarded without impersonation carries no credentials of the
	// proxy's own: it goes out on a transport built without them.
	var noAuthClientTransport http.RoundTripper
	if cfg.DisableImpersonation || cfg.TokenPassthrough {
		noAuthClientTransport, err = roundTripperForRestConfig(&rest.Config{
			APIPath: deps.RestConfig.APIPath,
			Host:    deps.RestConfig.Host,
			Timeout: deps.RestConfig.Timeout,
			TLSClientConfig: rest.TLSClientConfig{
				CAFile: deps.RestConfig.CAFile,
				CAData: deps.RestConfig.CAData,
			},
		})
		if err != nil {
			return nil, err
		}
	}

	return &Proxy{
		metrics:                  deps.Metrics,
		restConfig:               deps.RestConfig,
		requestLogger:            logging.ForComponent(deps.Logger, logging.ComponentRequest),
		oidcLogger:               logging.ForComponent(deps.Logger, logging.ComponentOIDC),
		tokenReviewLogger:        logging.ForComponent(deps.Logger, logging.ComponentTokenReview),
		upstreamLogger:           logging.ForComponent(deps.Logger, logging.ComponentUpstream),
		clientTransport:          clientTransport,
		noAuthClientTransport:    noAuthClientTransport,
		tokenReviewer:            deps.TokenReviewer,
		subjectAccessReviewer:    deps.SubjectAccessReviewer,
		secureServingInfo:        deps.SecureServingInfo,
		config:                   &cfg,
		trustedProxies:           trustedProxies,
		allowedReservedGroups:    allowedReservedGroups,
		oidcRequestAuthenticator: bearertoken.New(deps.OIDCTokenAuthenticator),
		auditor:                  deps.Auditor,
		warnLimiter:              logging.NewLimiter(warnLimiterRate, warnLimiterBurst, warnLimiterInterval, nil),
	}, nil
}

// Start wires up the reverse-proxy handler chain and serves until ctx is
// cancelled. It returns once the listener is serving; Wait blocks until it has
// stopped. The caller has already started the auditor's backend.
func (p *Proxy) Start(ctx context.Context) error {
	upstream, err := url.Parse(p.restConfig.Host)
	if err != nil {
		return fmt.Errorf("proxy: parsing API server URL %q: %w", p.restConfig.Host, err)
	}

	proxyHandler := httputil.NewSingleHostReverseProxy(upstream)
	proxyHandler.Transport = roundTripperFunc(p.roundTrip)
	proxyHandler.ErrorHandler = p.handleUpstreamError
	proxyHandler.FlushInterval = p.config.FlushInterval
	// Every failure the reverse proxy can hand to a handler goes to
	// ErrorHandler. What it only logs -- an upstream body that broke mid-copy,
	// which the terminal record already reports as a termination -- arrives
	// as a WARN on the upstream component rather than as plain text on stderr.
	proxyHandler.ErrorLog = slog.NewLogLogger(p.upstreamLogger.Handler(), slog.LevelWarn)

	go p.warnLimiter.Run(ctx, p.requestLogger)

	// The apiserver's Serve stops on a closed channel, which is what the
	// context's Done channel is.
	stopped, listenerStopped, err := p.secureServingInfo.Serve(p.withFilterChain(proxyHandler), time.Second*60, ctx.Done())
	if err != nil {
		return fmt.Errorf("proxy: serving: %w", err)
	}
	p.stopped, p.listenerStopped = stopped, listenerStopped
	return nil
}

// Wait blocks until the listener has stopped accepting and serving has fully
// stopped. Before a successful Start there is nothing to wait for.
func (p *Proxy) Wait() {
	if p.stopped == nil {
		return
	}
	<-p.listenerStopped
	<-p.stopped
}

// roundTripperFunc adapts a function to http.RoundTripper, so the reverse
// proxy's transport need not be an exported method of Proxy.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// roundTrip is the reverse proxy's transport: it forwards an admitted request
// to the API server the way the filter chain decided.
func (p *Proxy) roundTrip(req *http.Request) (*http.Response, error) {
	imp := reqctx.Impersonation(req)
	if imp == nil {
		return nil, errNoImpersonationConfig
	}

	// Record the admitted request. Written before the upstream call so a watch
	// or exec that runs for hours still produces its access record immediately.
	p.recordDecision(req, accesslog.Decision{
		Allowed:      true,
		AuthMethod:   reqctx.AuthMethod(req),
		Inbound:      imp.InboundUser,
		Impersonated: imp.ImpersonatedUser,
	})

	if imp.Mode == reqctx.ForwardImpersonating {
		return transport.NewImpersonatingRoundTripper(*imp.Outbound, p.clientTransport).RoundTrip(req)
	}

	// The other modes forward with no credentials of the proxy's own. The
	// passthrough path left the client's bearer token in place, so the API
	// server authenticates it; on the disabled path OIDC authentication
	// consumed the token, so the request arrives anonymous.
	return p.noAuthClientTransport.RoundTrip(req)
}

// reviewToken asks the API server's TokenReview whether it accepts the
// request's bearer token, recording the attempt. It returns nil when the token
// is accepted, errUnauthorized when it is missing or rejected, and the
// reviewer's own error, wrapping tokenreview.ErrCreateTokenReview, when the
// reviewer could not answer.
func (p *Proxy) reviewToken(req *http.Request) error {
	ctx := req.Context()

	bearer, found := bearerToken(req)
	if !found {
		logging.Emit(ctx, p.tokenReviewLogger, logging.EventAuthnTokenMissing)
		p.metrics.AuthenticationAttempt(metrics.AuthMethodTokenReview, metrics.AuthRejected)
		return errUnauthorized
	}

	_, ok, err := p.tokenReviewer.AuthenticateToken(ctx, bearer)
	if err != nil {
		// As for authz.sar.failed: a review that failed because the client
		// itself went away is a per-request condition at DEBUG, so a client
		// cannot drive the ERROR stream by hanging up mid-request.
		reason, level := metrics.ReasonAuthenticationDependencyError, slog.LevelError
		if reqctx.ClientGone(ctx, err) {
			reason, level = metrics.ReasonClientCanceled, slog.LevelDebug
		}
		logging.EmitLevel(ctx, p.tokenReviewLogger, logging.EventAuthnTokenReviewFailed, level,
			slog.String("reason", string(reason)), logging.ErrAttr(err))
		p.metrics.AuthenticationAttempt(metrics.AuthMethodTokenReview, metrics.AuthError)
		return err
	}

	// The reviewer answered, and it has already recorded the outcome: a live
	// TokenReview emits authn.tokenreview.completed with its duration, a cache
	// hit emits cache.tokenreview.lookup with the cached verdict. A rejection
	// is such an answer, not a failure, so nothing more is recorded here.
	if !ok {
		p.metrics.AuthenticationAttempt(metrics.AuthMethodTokenReview, metrics.AuthRejected)
		return errUnauthorized
	}
	p.metrics.AuthenticationAttempt(metrics.AuthMethodTokenReview, metrics.AuthAccepted)
	return nil
}

// recordDecision writes the one access record a request produces and counts
// it. Every decision goes through here, so the metric and the record can never
// disagree about what was decided, and this is where the one-per-request rule
// is kept: roundTrip records an admitted request before the upstream call, so
// a failure arriving after that -- a client that cancelled, an upstream that
// broke -- has no decision left to make and is dropped here.
func (p *Proxy) recordDecision(req *http.Request, d accesslog.Decision) {
	if reqctx.DecisionRecorded(req) {
		return
	}
	accesslog.LogDecision(p.requestLogger, req, d)
	reqctx.MarkDecisionRecorded(req)
	p.metrics.AccessDecision(d.AuthMethod, d.Allowed, d.Reason)
}

func roundTripperForRestConfig(config *rest.Config) (http.RoundTripper, error) {
	// client-go's transport reloads file-backed client certificates and closes
	// connections that still use the previous certificate. Restrict ALPN to
	// HTTP/1.1 because Kubernetes streaming requests upgrade to SPDY.
	configCopy := rest.CopyConfig(config)
	configCopy.NextProtos = []string{"http/1.1"}
	clientRT, err := rest.TransportFor(configCopy)
	if err != nil {
		return nil, fmt.Errorf("proxy: building API server transport: %w", err)
	}

	return clientRT, nil
}
