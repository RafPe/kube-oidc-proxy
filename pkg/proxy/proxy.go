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

	"github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/accesslog"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
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
	impersonationAuthorizer  *subjectaccessreview.Authorizer
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
// The Proxy borrows every collaborator for its lifetime; it does not close or
// mutate them. That includes the auditor: the proxy only wraps requests in its
// audit chains, while the caller starts the backend before Start and flushes
// it once the proxy has stopped serving.
type Dependencies struct {
	RestConfig *rest.Config

	// OIDCTokenAuthenticator verifies the bearer tokens issued by the
	// configured OIDC issuers. Its errors are not classified: every error it
	// returns, an issuer whose keys have not been fetched yet included, is
	// treated as a rejected token -- counted as an OIDC rejection, recorded as
	// authn.oidc.failed with reason=unauthorized, and handed to the
	// token-review filter, which refuses it 401 unless token passthrough is
	// on. A token no issuer claims (ok=false with a nil error) takes the same
	// path: New wraps the authenticator in bearertoken, which reports that
	// answer as an invalid-token error. Only a request carrying no bearer
	// token at all is refused 401 without the token-review filter.
	OIDCTokenAuthenticator authenticator.Token

	// Auditor records the audit events of every request the proxy handles,
	// refused ones included, and supplies the request resolution and
	// long-running rule the whole chain shares (see package audit). Required;
	// an auditor built from nil options configures no backend but keeps every
	// audit filter in the chain.
	Auditor *audit.Audit

	// TokenReviewer authenticates passthrough bearer tokens, typically the
	// authenticator tokenreview.New returns, which applies the result cache
	// its Config asks for and records every outcome itself, a failure
	// included (authn.tokenreview.failed). A review that could not be
	// answered must return an error wrapping tokenreview.ErrCreateTokenReview:
	// that is what refuses the request as a dependency failure (401, reason
	// authentication_dependency_error). Any other error is the proxy's own
	// failure and answers 500.
	TokenReviewer authenticator.Token

	// ImpersonationAuthorizer authorizes the Impersonate-* headers a client
	// sends, through SubjectAccessReviews.
	ImpersonationAuthorizer *subjectaccessreview.Authorizer

	SecureServingInfo *server.SecureServingInfo

	// Metrics is the process recorder. Optional: nil records nothing.
	Metrics *metrics.Recorder
}

// New validates cfg and deps and constructs a Proxy. Invalid configurations
// and missing collaborators fail here, at construction, rather than on the
// first request.
//
// root is the process root logger. New derives the request, oidc, tokenreview
// and upstream component loggers from it, so it takes the root rather than any
// one of them. A nil root is a wiring bug rather than a configuration error,
// so it panics.
//
// New takes ownership of cfg: it copies the ExtraUserHeaders map, so later
// mutation of the caller's map does not change proxy behavior.
func New(cfg Config, deps Dependencies, root *slog.Logger) (*Proxy, error) {
	if root == nil {
		panic("proxy: New called with a nil logger")
	}
	if deps.RestConfig == nil {
		return nil, errors.New("proxy: RestConfig is required")
	}
	if deps.OIDCTokenAuthenticator == nil {
		return nil, errors.New("proxy: OIDCTokenAuthenticator is required")
	}
	if deps.ImpersonationAuthorizer == nil {
		return nil, errors.New("proxy: ImpersonationAuthorizer is required")
	}
	if deps.SecureServingInfo == nil {
		return nil, errors.New("proxy: SecureServingInfo is required")
	}
	if deps.Auditor == nil {
		return nil, errors.New("proxy: Auditor is required")
	}
	// Reject inconsistent combinations: token-review handling has no reviewer to
	// call, so enabling it without one can never work.
	if cfg.TokenPassthrough && deps.TokenReviewer == nil {
		return nil, errors.New("proxy: TokenPassthrough enabled but no TokenReviewer provided")
	}

	// Copy the mutable map at the construction boundary so that mutating the
	// caller's map after New cannot alter proxy behavior. The two slices need
	// no copy: they are read only here, and parsed into values of the Proxy's
	// own.
	cfg.ExtraUserHeaders = cloneExtra(cfg.ExtraUserHeaders)

	// Validate trusted-proxy CIDRs up front so a bad configuration fails at
	// construction rather than silently trusting nothing at request time.
	trustedProxies, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}

	// Validate the reserved-group allowlist up front: an entry that is not
	// reserved is a no-op the operator almost certainly did not intend.
	allowedReservedGroups, err := parseAllowedReservedGroups(cfg.AllowedReservedGroups)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
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
		requestLogger:            logging.ForComponent(root, logging.ComponentRequest),
		oidcLogger:               logging.ForComponent(root, logging.ComponentOIDC),
		tokenReviewLogger:        logging.ForComponent(root, logging.ComponentTokenReview),
		upstreamLogger:           logging.ForComponent(root, logging.ComponentUpstream),
		clientTransport:          clientTransport,
		noAuthClientTransport:    noAuthClientTransport,
		tokenReviewer:            deps.TokenReviewer,
		impersonationAuthorizer:  deps.ImpersonationAuthorizer,
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
	proxyHandler, err := p.reverseProxy()
	if err != nil {
		return err
	}

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

// reverseProxy builds the handler at the bottom of the filter chain: the
// reverse proxy that forwards an admitted request to the API server through
// roundTrip and answers its failures through handleUpstreamError.
func (p *Proxy) reverseProxy() (*httputil.ReverseProxy, error) {
	upstream, err := url.Parse(p.restConfig.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy: parsing API server URL %q: %w", p.restConfig.Host, err)
	}

	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.Transport = roundTripperFunc(p.roundTrip)
	rp.ErrorHandler = p.handleUpstreamError
	rp.FlushInterval = p.config.FlushInterval
	// Every failure the reverse proxy can hand to a handler goes to
	// ErrorHandler. What it only logs -- an upstream body that broke mid-copy,
	// which the terminal record already reports as a termination -- arrives
	// as a WARN on the upstream component rather than as plain text on stderr.
	rp.ErrorLog = slog.NewLogLogger(p.upstreamLogger.Handler(), slog.LevelWarn)
	return rp, nil
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
// reviewer could not answer. The reviewer records every outcome it reaches,
// a failure included, so only the metric is counted here.
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
		p.metrics.AuthenticationAttempt(metrics.AuthMethodTokenReview, metrics.AuthError)
		return err
	}

	// The reviewer answered, and it has already recorded the outcome: a live
	// TokenReview emits authn.tokenreview.completed with its duration, a cache
	// hit emits cache.tokenreview.lookup with the cached verdict.
	if !ok {
		p.metrics.AuthenticationAttempt(metrics.AuthMethodTokenReview, metrics.AuthRejected)
		return errUnauthorized
	}
	p.metrics.AuthenticationAttempt(metrics.AuthMethodTokenReview, metrics.AuthAccepted)
	return nil
}

// recordDecision writes the one access record a request produces and counts
// it. Every decision goes through here, which is what keeps the metric and the
// record in step, and this is where the one-per-request rule is kept:
// roundTrip records an admitted request before the upstream call, so a failure
// arriving after that -- a client that cancelled, an upstream that broke --
// has no decision left to make and is dropped here.
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
