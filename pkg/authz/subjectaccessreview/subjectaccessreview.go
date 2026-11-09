// Copyright Jetstack Ltd. See LICENSE for details.

// Package subjectaccessreview authorizes impersonation requests by submitting
// SubjectAccessReviews to the API server.
//
// It also owns the impersonation-header grammar: which request headers are
// impersonation headers (any Impersonate- prefix, in any case), which kinds of
// them the proxy knows, and how an Impersonate-Extra- header decodes to a key.
// Authorizer.ConsumeImpersonation is the one entry point: it authorizes every
// such header and returns the request to forward without them, so no caller
// needs the grammar to keep a client's raw headers from travelling on under
// the proxy's own credentials.
//
// Every error a caller acts on is a sentinel or matches one (an
// *ImpersonationAuthError matches ErrImpersonationNotAllowed), so callers
// classify errors with errors.Is, never by matching message text.
package subjectaccessreview

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/sync/singleflight"
	"k8s.io/apiserver/pkg/authentication/user"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/clock"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

var (
	// ErrNoImpersonationUser is the sentinel for a request that carries
	// Impersonate-Group, -Uid or -Extra-* headers but no Impersonate-User: the
	// other kinds refine a user, so without one there is nothing to
	// impersonate. The message is client-facing and stable.
	ErrNoImpersonationUser = errors.New("no Impersonate-User header found for request")

	// ErrUnknownImpersonationHeader is the sentinel for a request carrying an
	// Impersonate- prefixed header of a kind this proxy does not know. It is
	// refused rather than forwarded or ignored: an impersonation attempt the
	// proxy cannot authorize must not travel on. The header name is wrapped
	// alongside it for the client-facing message.
	ErrUnknownImpersonationHeader = errors.New("unknown impersonation header")

	// ErrUnforwardableExtraKey is the sentinel for an Impersonate-Extra- header
	// whose decoded key the proxy cannot forward unchanged: client-go encodes
	// the key into a header name and the API server lower-cases and decodes it
	// again, so a key that does not survive that round trip (one carrying
	// upper case, such as %41bc decoding to "Abc") would be authorized under
	// one name and asserted upstream under another. Like
	// ErrUnknownImpersonationHeader it refuses the request on its shape,
	// before any review is sent; the header name is wrapped alongside it for
	// the client-facing message.
	ErrUnforwardableExtraKey = errors.New("impersonation extra key cannot be forwarded unchanged")

	// ErrCreateSubjectAccessReview is the sentinel wrapping a failure to submit a
	// SubjectAccessReview to the API server. The underlying error (including
	// context.Canceled/DeadlineExceeded) is wrapped alongside it.
	ErrCreateSubjectAccessReview = errors.New("create SubjectAccessReview")

	// ErrImpersonationNotAllowed is the sentinel that classifies an authorization
	// denial: the requester is not permitted to impersonate a requested resource.
	// Every denial ConsumeImpersonation returns is an *ImpersonationAuthError,
	// which matches it.
	ErrImpersonationNotAllowed = errors.New("not allowed to impersonate")

	// ErrTooManyImpersonationHeaderValues is the sentinel that classifies a
	// request carrying more impersonation header values than the configured cap.
	// Each value costs one SubjectAccessReview round trip to the API server, so
	// the count is capped before any review is sent. It is not an authorization
	// decision, so it does not match ErrImpersonationNotAllowed.
	ErrTooManyImpersonationHeaderValues = errors.New("too many impersonation header values")
)

// TargetKind is one of the closed set of impersonation target kinds, as the
// access record's target_kind reports them and ImpersonationAuthError carries
// them.
type TargetKind string

const (
	TargetUser  TargetKind = "user"
	TargetGroup TargetKind = "group"
	TargetUID   TargetKind = "uid"
	TargetExtra TargetKind = "extra"
)

// ImpersonationAuthError reports that a requester is not authorized to
// impersonate a particular target. It matches ErrImpersonationNotAllowed, and
// it carries the refused target as structured fields for the access record.
type ImpersonationAuthError struct {
	// Requester is the name of the authenticated user attempting impersonation.
	Requester string

	// Kind is one of TargetUser, TargetGroup, TargetUID or TargetExtra.
	Kind TargetKind

	// Target is the refused name: the user, group or uid, or for TargetExtra
	// the refused value of the extra.
	Target string

	// ExtraKey is the extra's key when Kind is TargetExtra, and "" otherwise.
	ExtraKey string
}

// Error renders the stable, client-facing denial.
func (e *ImpersonationAuthError) Error() string {
	if e.Kind == TargetExtra {
		return fmt.Sprintf("%s is not allowed to impersonate extra info '%s'='%s'", e.Requester, e.ExtraKey, e.Target)
	}
	return fmt.Sprintf("%s is not allowed to impersonate %s '%s'", e.Requester, e.Kind, e.Target)
}

// TargetName is the refused target as the access record's target_name reports
// it: the bare name, or key=value for an extra.
func (e *ImpersonationAuthError) TargetName() string {
	if e.Kind == TargetExtra {
		return e.ExtraKey + "=" + e.Target
	}
	return e.Target
}

// Is matches ErrImpersonationNotAllowed.
func (e *ImpersonationAuthError) Is(target error) bool {
	return target == ErrImpersonationNotAllowed
}

// DefaultTimeout is the budget a zero Config.Timeout means. The SAR client
// inherits rest.Config.Timeout, which defaults to none, so this budget is what
// stops a stalled API server holding a client connection open.
const DefaultTimeout = 5 * time.Second

// DefaultMaxHeaderValues is the cap a zero Config.MaxHeaderValues means on the
// impersonation header values one request may carry. Each value costs one
// serial SubjectAccessReview round trip; 64 is well above what kubectl
// --as/--as-group or programmatic group forwarding send.
const DefaultMaxHeaderValues = 64

// Authorizer authorizes impersonation requests by submitting a
// SubjectAccessReview to the API server for each impersonated target. A
// single shared timeout budget bounds the whole sequence of checks performed
// for one request.
type Authorizer struct {
	// logger is the sar-component logger every record this authorizer emits
	// goes through, so each carries component=sar. The per-request correlation
	// id travels on the call's context instead, never bound onto a logger, and
	// Emit reads it from there.
	logger *slog.Logger

	// metrics receives the API-call and cache observations; nil records nothing.
	metrics *metrics.Recorder

	client clientazv1.SubjectAccessReviewInterface

	// timeout is the single shared budget applied across the whole sequence
	// of SAR checks for one request.
	timeout time.Duration

	// maxHeaderValues caps the total number of impersonation header values a
	// single request may carry. Requests over the cap are rejected before any
	// SAR is sent.
	maxHeaderValues int

	// cache holds definitive allow/deny decisions keyed by the serialized
	// review spec. nil means caching is switched off: every check goes to the
	// API server and no cache lookup is recorded.
	cache *decisionCache

	// flight deduplicates concurrent live checks for the same review spec so a
	// burst of identical requests results in a single SubjectAccessReview call.
	// Only used when the cache is enabled.
	flight singleflight.Group
}

// Config is the operator-facing configuration of an Authorizer.
type Config struct {
	// Timeout is the single shared budget for the whole sequence of checks
	// one request needs; zero or negative means DefaultTimeout.
	Timeout time.Duration

	// AllowCacheTTL and DenyCacheTTL bound how long a definitive allowed or
	// denied decision is served from memory; zero disables that class of
	// caching, and both zero switch the cache off. See New for the trade-off.
	AllowCacheTTL time.Duration
	DenyCacheTTL  time.Duration

	// MaxHeaderValues caps the impersonation header values one request may
	// carry; zero or negative means DefaultMaxHeaderValues.
	MaxHeaderValues int

	// Metrics receives the API-call and cache observations. Optional: nil
	// records nothing.
	Metrics *metrics.Recorder
}

// New returns an Authorizer that authorizes impersonation through client,
// bounding the whole sequence of checks for a single request by cfg.Timeout and
// refusing requests that carry more than cfg.MaxHeaderValues impersonation
// header values. Both follow one rule: zero or negative means the package
// default, settled here, so neither an expired budget nor an unbounded value
// count is constructible.
//
// cfg.AllowCacheTTL and cfg.DenyCacheTTL bound how long a definitive allowed
// or denied decision is served from an in-memory cache before being re-checked
// against the API server; errors are never cached. Caching trades revocation
// lag for load: an RBAC revoke can take up to AllowCacheTTL to be enforced for
// a cached allow, and a newly granted permission up to DenyCacheTTL to be
// honoured. Set both to 0 to switch the cache off and re-check on every
// request.
//
// logger is the sar-component logger; New panics when it is nil.
func New(client clientazv1.SubjectAccessReviewInterface, cfg Config, logger *slog.Logger) *Authorizer {
	if logger == nil {
		panic("subjectaccessreview: nil logger")
	}

	// A zero budget would hand every review an already expired context and
	// deny every impersonating request, and a zero cap would refuse every
	// impersonating request, so both are settled here, at construction, the
	// way tokenreview.New settles its timeout.
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxHeaderValues := cfg.MaxHeaderValues
	if maxHeaderValues <= 0 {
		maxHeaderValues = DefaultMaxHeaderValues
	}

	return &Authorizer{
		logger:          logger,
		metrics:         cfg.Metrics,
		client:          client,
		timeout:         timeout,
		maxHeaderValues: maxHeaderValues,
		cache:           newDecisionCache(cfg.AllowCacheTTL, cfg.DenyCacheTTL, decisionCacheSize, clock.RealClock{}),
	}
}

// ConsumeImpersonation authorizes the request's impersonation headers and
// returns the request to forward and the identity it impersonates.
//
// A request with no impersonation header is returned as is with a nil target,
// and no review is sent. Otherwise every requested target is reviewed in a
// fixed order whatever order the header map iterates in -- the user, then each
// group, then each extra by key, then the uid -- so a request refused on
// several targets is always refused on the same one. An authorization denial
// is an *ImpersonationAuthError.
//
// On success the returned request is a shallow copy of req whose header map
// is a fresh copy without any impersonation header; req itself is not
// modified. The headers must not travel on: client-go's impersonating round
// tripper leaves a request that already carries Impersonate-User untouched,
// which would forward the client's raw headers under the proxy's own
// credentials.
func (a *Authorizer) ConsumeImpersonation(req *http.Request, requester user.Info) (*http.Request, user.Info, error) {
	if !hasImpersonationHeaders(req.Header) {
		return req, nil, nil
	}

	target, err := a.resolveImpersonation(req, requester)
	if err != nil {
		return nil, nil, err
	}

	forward := req.WithContext(req.Context())
	forward.Header = stripImpersonationHeaders(req.Header)
	return forward, target, nil
}

// resolveImpersonation reviews the impersonation headers of a request that
// carries at least one and returns the identity they ask for.
func (a *Authorizer) resolveImpersonation(req *http.Request, requester user.Info) (user.Info, error) {
	// Refuse over-wide requests before spending anything: every impersonation
	// header value below costs one serial SAR round trip, and the value count
	// is entirely client-controlled. Counting mirrors parseImpersonation
	// (case-insensitive Impersonate- prefix over every key's values), so no
	// header-case variant or duplicate key can be consumed without having been
	// counted.
	if count := countImpersonationHeaderValues(req.Header); count > a.maxHeaderValues {
		return nil, fmt.Errorf("%w: request carries %d impersonation header values, the limit is %d",
			ErrTooManyImpersonationHeaderValues, count, a.maxHeaderValues)
	}

	// The request's shape is settled before any review is sent, so a malformed
	// request costs nothing.
	targetUser, targets, err := parseImpersonation(req.Header)
	if err != nil {
		return nil, err
	}

	// Derive one shared budget for the whole SAR sequence from the inbound
	// request context, so client cancellation propagates and a stalled API
	// server cannot stall the request indefinitely.
	budget, cancel := context.WithTimeout(req.Context(), a.timeout)
	defer cancel()
	call := reviewCall{ctx: budget, requestCtx: req.Context(), requester: requester}

	for _, target := range targets {
		if err := a.authorize(call, target); err != nil {
			return nil, err
		}
	}

	logging.Emit(budget, a.logger, logging.EventAuthzImpersonationResolved,
		slog.String("target_kind", string(TargetUser)),
		slog.String("target_name", logging.Bound(targetUser.Name, logging.MaxIdentity)))

	return targetUser, nil
}

// authorize asks the API server whether requester may impersonate target and
// returns the typed denial when it may not. A dependency failure is returned
// as is: it is not a verdict on the request.
func (a *Authorizer) authorize(call reviewCall, target impersonationTarget) error {
	allowed, err := a.cachedCheck(call, target)
	if err != nil {
		return err
	}
	if !allowed {
		return target.denial(call.requester)
	}
	return nil
}
