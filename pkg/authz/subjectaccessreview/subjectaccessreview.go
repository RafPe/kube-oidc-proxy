// Copyright Jetstack Ltd. See LICENSE for details.

// Package subjectaccessreview authorizes impersonation requests by submitting
// SubjectAccessReviews to the API server. It exposes typed, sentinel-backed
// errors so HTTP handlers can select a response status via errors.Is rather
// than by matching message text.
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
	// SubjectAccessReview to the API server. Callers can match it with errors.Is;
	// the underlying error (including context.Canceled/DeadlineExceeded) is wrapped
	// alongside it so it remains detectable too.
	ErrCreateSubjectAccessReview = errors.New("create SubjectAccessReview")

	// ErrImpersonationNotAllowed is the sentinel that classifies an authorization
	// denial: the requester is not permitted to impersonate a requested resource.
	// Every denial returned by ResolveImpersonation is an
	// *ImpersonationAuthError, which matches this sentinel via errors.Is. HTTP
	// handlers select a 403 with errors.Is(err, ErrImpersonationNotAllowed)
	// instead of matching on message text.
	ErrImpersonationNotAllowed = errors.New("not allowed to impersonate")

	// ErrTooManyImpersonationHeaderValues is the sentinel that classifies a
	// request carrying more impersonation header values than the configured cap.
	// Each value costs one SubjectAccessReview round trip to the API server, so
	// the count is capped before any review is sent. HTTP handlers select a 431
	// with errors.Is; this is not an authorization decision, so it deliberately
	// does not classify as ErrImpersonationNotAllowed.
	ErrTooManyImpersonationHeaderValues = errors.New("too many impersonation header values")
)

// TargetKind is one of the closed set of impersonation target kinds, as the
// access record's target_kind reports them. It is also the vocabulary
// ImpersonationAuthError speaks, so the proxy never has to recover a kind from
// message text.
type TargetKind string

const (
	TargetUser  TargetKind = "user"
	TargetGroup TargetKind = "group"
	TargetUID   TargetKind = "uid"
	TargetExtra TargetKind = "extra"
)

// ImpersonationAuthError reports that a requester is not authorized to
// impersonate a particular target. It classifies as ErrImpersonationNotAllowed
// through errors.Is so callers can select an HTTP 403 without inspecting the
// message string, and it carries the refused target as structured fields so
// the access record never parses the client-facing message.
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

// Is reports whether e should be treated as ErrImpersonationNotAllowed, letting
// errors.Is classify any denial regardless of the concrete resource involved.
func (e *ImpersonationAuthError) Is(target error) bool {
	return target == ErrImpersonationNotAllowed
}

// DefaultTimeout is the default value for the SAR authorization budget, and
// what a zero Config.Timeout means. It bounds the total time spent authorizing
// a single request's impersonation via SubjectAccessReviews. It covers the
// whole sequence of checks, not each call, so a stalled API server cannot hold
// a client connection open indefinitely (the SAR client inherits
// rest.Config.Timeout, which defaults to zero).
const DefaultTimeout = 5 * time.Second

// DefaultMaxHeaderValues is the default cap, and what a zero
// Config.MaxHeaderValues means, on the total number of
// impersonation header values accepted per request (one Impersonate-User plus
// every Impersonate-Group, Impersonate-Uid and Impersonate-Extra-* value).
// Each value costs one serial SubjectAccessReview round trip to the API
// server, so the count bounds the per-request amplification a client can
// drive. kube-apiserver itself places no count limit on impersonation values
// (only its ~1MiB total header size limit applies, which admits thousands of
// values), but its per-value authorization is an in-process check, not a
// network call. 64 comfortably covers realistic clients — kubectl --as/
// --as-group sends a handful of values, and programmatic identity forwarding
// rarely exceeds a few dozen groups — while keeping the worst case at 64
// round trips inside the shared timeout budget.
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

// ResolveImpersonation inspects the request's impersonation headers,
// verifies via SubjectAccessReview that requester is allowed to impersonate
// each requested target, and returns the resulting impersonated user. The
// caller only calls it for a request HasImpersonationHeaders reports
// impersonation headers on. An authorization denial is returned as an
// *ImpersonationAuthError, which matches ErrImpersonationNotAllowed via
// errors.Is.
//
// Targets are reviewed in a fixed order whatever order the header map
// iterates in -- the user, then each group, then each extra by key, then the
// uid -- so a request refused on several targets is always refused on the same
// one.
//
// The request is read, never modified. The caller forwards the request, so the
// caller removes the consumed headers (StripImpersonationHeaders) before client-go's
// impersonating round tripper sees it: that round tripper leaves a request
// that already carries Impersonate-User untouched, which would forward the
// client's raw headers under the proxy's own credentials.
func (a *Authorizer) ResolveImpersonation(req *http.Request, requester user.Info) (user.Info, error) {
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
