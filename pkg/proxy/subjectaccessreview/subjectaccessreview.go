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
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/authentication/user"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/transport"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

var (
	// ErrNoImpersonationUser is the sentinel for a request that carries
	// Impersonate-Group, -Uid or -Extra-* headers but no Impersonate-User: the
	// other kinds refine a user, so without one there is nothing to
	// impersonate. The message is client-facing and stable.
	ErrNoImpersonationUser = errors.New("no Impersonation-User header found for request")

	// ErrCreateSubjectAccessReview is the sentinel wrapping a failure to submit a
	// SubjectAccessReview to the API server. Callers can match it with errors.Is;
	// the underlying error (including context.Canceled/DeadlineExceeded) is wrapped
	// alongside it so it remains detectable too.
	ErrCreateSubjectAccessReview = errors.New("create SubjectAccessReview")

	// ErrImpersonationNotAllowed is the sentinel that classifies an authorization
	// denial: the requester is not permitted to impersonate a requested resource.
	// Every denial returned by CheckAuthorizedForImpersonation is an
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

// The closed set of impersonation target kinds, as the access record's
// target_kind reports them. They are also the vocabulary ImpersonationAuthError
// speaks, so the proxy never has to recover a kind from message text.
const (
	TargetUser  = "user"
	TargetGroup = "group"
	TargetUID   = "uid"
	TargetExtra = "extra"
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
	Kind string

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

// DefaultTimeout is the default value for the SAR authorization budget. It
// bounds the total time spent authorizing a single request's impersonation via
// SubjectAccessReviews. It covers the whole sequence of checks, not each call,
// so a stalled API server cannot hold a client connection open indefinitely
// (the SAR client inherits rest.Config.Timeout, which defaults to zero).
const DefaultTimeout = 5 * time.Second

// DefaultMaxHeaderValues is the default cap on the total number of
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

// SubjectAccessReview authorizes impersonation requests by submitting a
// SubjectAccessReview to the API server for each impersonated resource. A
// single shared timeout budget bounds the whole sequence of checks performed
// for one request.
type SubjectAccessReview struct {
	// logger is the sar-component logger every record this reviewer emits goes
	// through, so each carries component=sar. The per-request correlation id
	// travels on the call's context instead, never bound onto a logger, and
	// Emit reads it from there. Never nil: New substitutes a discarding logger
	// and log() covers a reviewer built without one.
	logger *slog.Logger

	// metrics receives the API-call and cache observations; nil records nothing.
	metrics *metrics.Recorder

	reviewer clientazv1.SubjectAccessReviewInterface

	// sarTimeout is the single shared budget applied across the whole sequence
	// of SAR checks for one request.
	sarTimeout time.Duration

	// maxHeaderValues caps the total number of impersonation header values a
	// single request may carry. Requests over the cap are rejected before any
	// SAR is sent.
	maxHeaderValues int

	// cache holds definitive allow/deny decisions keyed by the serialized
	// review spec. nil disables caching entirely (every check goes to the API
	// server).
	cache *decisionCache

	// flight deduplicates concurrent live checks for the same review spec so a
	// burst of identical requests results in a single SubjectAccessReview call.
	// Only used when the cache is enabled.
	flight singleflight.Group

	// beforeFlight, when set, is called just before a caller joins the flight
	// for its key. It exists for the tests that pin coalescing: they release
	// the in-flight review only once every joiner has reached this point,
	// instead of sleeping and hoping. Nil in production.
	beforeFlight func()
}

// Config is the operator-facing configuration of a SubjectAccessReview.
type Config struct {
	// Timeout is the single shared budget for the whole sequence of checks
	// one request needs. See DefaultTimeout.
	Timeout time.Duration

	// AllowCacheTTL and DenyCacheTTL bound how long a definitive allowed or
	// denied decision is served from memory; zero disables that class of
	// caching. See New for the trade-off.
	AllowCacheTTL time.Duration
	DenyCacheTTL  time.Duration

	// MaxHeaderValues caps the impersonation header values one request may
	// carry. See DefaultMaxHeaderValues.
	MaxHeaderValues int
}

// New returns a SubjectAccessReview that authorizes impersonation via reviewer,
// bounding the whole sequence of checks for a single request by cfg.Timeout and
// refusing requests that carry more than cfg.MaxHeaderValues impersonation
// header values. MaxHeaderValues must be greater than zero: every SAR costs a
// round trip, so an unbounded value count must not be constructible.
//
// allowCacheTTL and denyCacheTTL bound how long a definitive allowed or denied
// decision is served from an in-memory cache before being re-checked against
// the API server; errors are never cached. Caching trades revocation lag for
// load: an RBAC revoke can take up to allowCacheTTL to be enforced for a
// cached allow, and a newly granted permission up to denyCacheTTL to be
// honoured. Set both to 0 to disable the cache and re-check on every request.
func New(reviewer clientazv1.SubjectAccessReviewInterface, cfg Config, logger *slog.Logger) (*SubjectAccessReview, error) {
	sarTimeout, allowCacheTTL, denyCacheTTL, maxHeaderValues := cfg.Timeout, cfg.AllowCacheTTL, cfg.DenyCacheTTL, cfg.MaxHeaderValues
	if maxHeaderValues <= 0 {
		return nil, fmt.Errorf("maxHeaderValues must be greater than 0, got %d", maxHeaderValues)
	}
	logger = logging.OrDiscard(logger)
	return &SubjectAccessReview{
		logger:          logger,
		reviewer:        reviewer,
		sarTimeout:      sarTimeout,
		maxHeaderValues: maxHeaderValues,
		cache:           newDecisionCache(allowCacheTTL, denyCacheTTL, decisionCacheSize, realClock{}),
	}, nil
}

// WithMetrics sets the recorder the reviewer reports API calls and cache
// lookups to. A nil recorder records nothing.
func (s *SubjectAccessReview) WithMetrics(r *metrics.Recorder) *SubjectAccessReview {
	s.metrics = r
	return s
}

// realClock supplies wall-clock time to the decision cache; tests substitute a
// fake to exercise TTL expiry deterministically.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

var _ utilcache.Clock = realClock{}

// impersonationTarget is one identity attribute a request asks to impersonate:
// the SubjectAccessReview resource that authorizes it, the kind the record
// reports it under, and the name being asked for.
type impersonationTarget struct {
	kind     string
	resource string
	name     string

	// extraKey is the extra's key when kind is TargetExtra.
	extraKey string
}

// denial is the typed error a refused target is reported through.
func (t impersonationTarget) denial(requester user.Info) error {
	return &ImpersonationAuthError{
		Requester: requester.GetName(),
		Kind:      t.kind,
		Target:    t.name,
		ExtraKey:  t.extraKey,
	}
}

// CheckAuthorizedForImpersonation inspects the request's impersonation headers,
// verifies via SubjectAccessReview that requester is allowed to impersonate
// each requested target, and returns the resulting impersonated user. It
// returns a nil user.Info when the request carries no impersonation headers. An
// authorization denial is returned as an *ImpersonationAuthError, which matches
// ErrImpersonationNotAllowed via errors.Is.
//
// The request is read, never modified. The caller forwards the request, so the
// caller removes the consumed headers (StripImpersonationHeaders) before client-go's
// impersonating round tripper sees it: that round tripper leaves a request
// that already carries Impersonate-User untouched, which would forward the
// client's raw headers under the proxy's own credentials.
func (s *SubjectAccessReview) CheckAuthorizedForImpersonation(req *http.Request, requester user.Info) (user.Info, error) {
	// Refuse over-wide requests before spending anything: every impersonation
	// header value below costs one serial SAR round trip, and the value count
	// is entirely client-controlled. Counting mirrors the consumption loop
	// (case-insensitive Impersonate- prefix over every key's values), so no
	// header-case variant or duplicate key can be consumed without having been
	// counted.
	if count := countImpersonationHeaderValues(req.Header); count > s.maxHeaderValues {
		return nil, fmt.Errorf("%w: request carries %d impersonation header values, the limit is %d",
			ErrTooManyImpersonationHeaderValues, count, s.maxHeaderValues)
	}

	if !HasImpersonationHeaders(req.Header) {
		return nil, nil
	}
	// Groups, uids and extras refine a user; without one there is nothing to
	// impersonate.
	if req.Header.Get(transport.ImpersonateUserHeader) == "" {
		return nil, ErrNoImpersonationUser
	}

	// Derive one shared budget for the whole SAR sequence from the inbound
	// request context, so client cancellation propagates and a stalled API
	// server cannot stall the request indefinitely.
	ctx, cancel := context.WithTimeout(req.Context(), s.sarTimeout)
	defer cancel()
	ctx = withRequesterErr(ctx, req.Context().Err)

	targetUser := &user.DefaultInfo{
		Groups: make([]string, 0),
		Extra:  map[string][]string{},
	}

	for key, values := range req.Header {
		if !IsImpersonationHeader(key) {
			continue
		}

		switch {
		case strings.EqualFold(key, transport.ImpersonateUserHeader):
			target := impersonationTarget{kind: TargetUser, resource: "users", name: values[0]}
			if err := s.authorize(ctx, target, requester); err != nil {
				return nil, err
			}
			targetUser.Name = target.name

		case strings.EqualFold(key, transport.ImpersonateUIDHeader):
			target := impersonationTarget{kind: TargetUID, resource: "uids", name: values[0]}
			if err := s.authorize(ctx, target, requester); err != nil {
				return nil, err
			}
			targetUser.UID = target.name

		case strings.EqualFold(key, transport.ImpersonateGroupHeader):
			for _, group := range values {
				target := impersonationTarget{kind: TargetGroup, resource: "groups", name: group}
				if err := s.authorize(ctx, target, requester); err != nil {
					return nil, err
				}
				targetUser.Groups = append(targetUser.Groups, group)
			}

		case hasPrefixFold(key, transport.ImpersonateUserExtraHeaderPrefix):
			// Extra keys are lower-case by definition (user.Info documents it),
			// so the RBAC check and the forwarded identity both use that form.
			extraKey := strings.ToLower(key[len(transport.ImpersonateUserExtraHeaderPrefix):])
			for _, value := range values {
				target := impersonationTarget{kind: TargetExtra, resource: "userextras/" + extraKey, name: value, extraKey: extraKey}
				if err := s.authorize(ctx, target, requester); err != nil {
					return nil, err
				}
				targetUser.Extra[extraKey] = append(targetUser.Extra[extraKey], value)
			}

		default:
			return nil, fmt.Errorf("unknown impersonation header '%s'", key)
		}
	}

	logging.Emit(ctx, s.log(), logging.EventAuthzImpersonationResolved,
		slog.String("target_kind", TargetUser),
		slog.String("target_name", logging.Bound(targetUser.Name, logging.MaxIdentity)))

	return targetUser, nil
}

// authorize asks the API server whether requester may impersonate target and
// returns the typed denial when it may not. A dependency failure is returned
// as is: it is not a verdict on the request.
func (s *SubjectAccessReview) authorize(ctx context.Context, target impersonationTarget, requester user.Info) error {
	allowed, err := s.checkRbacImpersonationAuthorization(ctx, target, requester)
	if err != nil {
		return err
	}
	if !allowed {
		return target.denial(requester)
	}
	return nil
}

// IsImpersonationHeader reports whether key names an impersonation header.
// The match is on the Impersonate- prefix, case-insensitively: a header a
// client spells unusually, or one of a kind this proxy does not know, is still
// an impersonation attempt and must be authorized or refused, never forwarded.
func IsImpersonationHeader(key string) bool {
	return hasPrefixFold(key, "Impersonate-")
}

// HasImpersonationHeaders reports whether the headers carry any impersonation
// header at all, which is what decides whether a request goes through
// CheckAuthorizedForImpersonation.
func HasImpersonationHeaders(headers http.Header) bool {
	for key := range headers {
		if IsImpersonationHeader(key) {
			return true
		}
	}
	return false
}

// StripImpersonationHeaders returns a copy of headers without the
// impersonation headers, for the request that is forwarded once they have
// been authorized and turned into the outbound identity.
func StripImpersonationHeaders(headers http.Header) http.Header {
	out := make(http.Header, len(headers))
	for key, values := range headers {
		if IsImpersonationHeader(key) {
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	return out
}

// hasPrefixFold is strings.HasPrefix without regard to case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// countImpersonationHeaderValues returns the total number of impersonation
// header values the request carries: every value of every header
// IsImpersonationHeader matches, exactly as the consumption loop in
// CheckAuthorizedForImpersonation matches them.
func countImpersonationHeaderValues(headers http.Header) int {
	count := 0
	for key, values := range headers {
		if IsImpersonationHeader(key) {
			count += len(values)
		}
	}
	return count
}

// checkRbacImpersonationAuthorization validates that requester may impersonate
// the named resource and reports whether the check allowed the request. The
// decision comes from the cache when a definitive, unexpired one is present;
// otherwise a live SubjectAccessReview is submitted to the API server. A cache
// hit returns the same (allowed, nil) pair the live check produced, so callers
// build byte-identical *ImpersonationAuthError denials either way. Errors are
// never cached: a transient API-server failure fails only the requests that
// observed it.
func (s *SubjectAccessReview) checkRbacImpersonationAuthorization(ctx context.Context, target impersonationTarget, requester user.Info) (bool, error) {
	spec := impersonationReviewSpec(target.resource, target.name, requester)
	kind := target.kind

	key, cacheable := s.cache.key(&spec)
	if !cacheable {
		logging.Emit(ctx, s.log(), logging.EventCacheSARLookup, slog.String("cache_result", string(metrics.CacheBypass)))
		s.metrics.CacheLookup(metrics.ReviewSAR, metrics.CacheBypass)
		return s.timedLiveCheck(ctx, kind, false, &spec)
	}

	if allowed, ok := s.cache.get(key); ok {
		logging.Emit(ctx, s.log(), logging.EventCacheSARLookup,
			slog.String("cache_result", string(metrics.CacheHit)),
			slog.String("decision", string(metrics.DecisionFor(allowed))))
		s.metrics.CacheLookup(metrics.ReviewSAR, metrics.CacheHit)
		return allowed, nil
	}
	logging.Emit(ctx, s.log(), logging.EventCacheSARLookup, slog.String("cache_result", string(metrics.CacheMiss)))
	s.metrics.CacheLookup(metrics.ReviewSAR, metrics.CacheMiss)

	return s.sharedLiveCheck(ctx, kind, key, &spec)
}

// log returns the logger this reviewer emits through. It tolerates the
// zero-valued reviewer tests build directly, which New would have given a
// discarding logger.
func (s *SubjectAccessReview) log() *slog.Logger {
	return logging.OrDiscard(s.logger)
}

// timedLiveCheck runs one live check and records its outcome: a completed
// review carrying how long the caller waited and whether it shared another
// request's call, or a failure carrying the dependency error. Exactly one
// terminal record is emitted per authorization question a caller asks.
func (s *SubjectAccessReview) timedLiveCheck(ctx context.Context, kind string, coalesced bool, spec *v1.SubjectAccessReviewSpec) (bool, error) {
	start := time.Now()
	allowed, err := s.liveCheck(ctx, spec)
	s.observeLiveCheck(ctx, kind, start, coalesced, allowed, err)
	return allowed, err
}

// requesterErrKey carries the inbound request context's Err function into the
// derived authorization context.
type requesterErrKey struct{}

// withRequesterErr records how to ask whether the requester's own context is
// finished. The authorization context is derived from the request context with
// the SAR budget applied, so its own Err cannot tell the two deadlines apart;
// only the parent's can.
func withRequesterErr(ctx context.Context, errFn func() error) context.Context {
	return context.WithValue(ctx, requesterErrKey{}, errFn)
}

// requesterDone reports whether the requester itself has gone away. Without a
// recorded parent — a check called directly, as the unit tests do — ctx is the
// requester's own context and answers for itself.
func requesterDone(ctx context.Context) bool {
	if errFn, ok := ctx.Value(requesterErrKey{}).(func() error); ok {
		return errFn() != nil
	}
	return ctx.Err() != nil
}

// observeLiveCheck emits the terminal record for one live check begun at start.
// A failure is classified before it is recorded, and a context error is not
// self-explanatory: the authorization context carries both the requester's
// deadline and the proxy's own SAR budget. When the requester is the one that
// went away — a client disconnect, or its own deadline — the failure is a
// per-request condition at DEBUG, so a client cannot drive the ERROR stream
// simply by hanging up mid-request. When the requester is still waiting, the
// deadline that expired is the proxy's budget, which means the API server did
// not answer in time: that is a dependency failure and stays an ERROR.
func (s *SubjectAccessReview) observeLiveCheck(ctx context.Context, kind string, start time.Time, coalesced, allowed bool, err error) {
	if err != nil {
		reason, level, logged := "authorization_dependency_error", slog.LevelError, err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if requesterDone(ctx) {
				reason, level = "client_canceled", slog.LevelDebug
			} else {
				logged = fmt.Errorf("subject access review timed out after %s: %w", s.sarTimeout, err)
			}
		}
		logging.EmitLevel(ctx, s.log(), logging.EventAuthzSARFailed, level,
			slog.String("reason", reason),
			logging.ErrAttr(logged))
		return
	}
	logging.Emit(ctx, s.log(), logging.EventAuthzSARCompleted,
		slog.String("decision", string(metrics.DecisionFor(allowed))),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		slog.Bool("request_coalesced", coalesced),
		slog.String("target_kind", kind))
}

// sharedLiveCheck performs a live check deduplicated across concurrent callers
// asking the identical authorization question, caching the resulting decision.
// The winning caller's context governs the shared call, so a waiter whose
// flight fails with a context error not its own retries with a direct check
// rather than inheriting another request's cancellation.
func (s *SubjectAccessReview) sharedLiveCheck(ctx context.Context, kind, key string, spec *v1.SubjectAccessReviewSpec) (bool, error) {
	start := time.Now()

	if s.beforeFlight != nil {
		s.beforeFlight()
	}
	ch := s.flight.DoChan(key, func() (interface{}, error) {
		allowed, err := s.liveCheck(ctx, spec)
		if err != nil {
			return false, err
		}
		s.cache.put(key, allowed)
		return allowed, nil
	})

	select {
	case <-ctx.Done():
		// Our own request is done; do not wait on the shared flight.
		err := fmt.Errorf("%w: %w", ErrCreateSubjectAccessReview, ctx.Err())
		s.observeLiveCheck(ctx, kind, start, false, false, err)
		return false, err
	case res := <-ch:
		if res.Err != nil {
			if res.Shared && ctx.Err() == nil &&
				(errors.Is(res.Err, context.Canceled) || errors.Is(res.Err, context.DeadlineExceeded)) {
				// The foreign flight's failure was not ours to report; the retry
				// below emits this caller's one terminal record.
				return s.timedLiveCheck(ctx, kind, false, spec)
			}
			s.observeLiveCheck(ctx, kind, start, res.Shared, false, res.Err)
			return false, res.Err
		}
		allowed := res.Val.(bool)
		s.observeLiveCheck(ctx, kind, start, res.Shared, allowed, nil)
		return allowed, nil
	}
}

// liveCheck submits spec to the API server as a SubjectAccessReview and
// reports whether it allowed the request. It is the only place the API server
// is called, so it is where the review API-call metric is observed: a caller
// served by the cache or by a coalesced in-flight call never reaches here.
func (s *SubjectAccessReview) liveCheck(ctx context.Context, spec *v1.SubjectAccessReviewSpec) (bool, error) {
	clusterSubjectAccessReview := v1.SubjectAccessReview{Spec: *spec}

	start := time.Now()
	reviewResult, err := s.reviewer.Create(ctx, &clusterSubjectAccessReview, metav1.CreateOptions{})
	allowed := err == nil && reviewResult.Status.Allowed
	s.metrics.ReviewRequest(metrics.ReviewSAR, metrics.ReviewOutcomeFor(err, allowed), time.Since(start))
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrCreateSubjectAccessReview, err)
	}
	return reviewResult.Status.Allowed, nil
}

// impersonationReviewSpec builds the SubjectAccessReviewSpec asking whether
// requester may impersonate the named resource. The same spec is both
// submitted to the API server and serialized as the cache key, so every field
// that can influence the decision — including the requester's UID and Extra
// fields — is part of the key by construction.
func impersonationReviewSpec(resource string, name string, requester user.Info) v1.SubjectAccessReviewSpec {
	extras := map[string]v1.ExtraValue{}
	var group string
	var subresource string

	for key, value := range requester.GetExtra() {
		extras[key] = value
	}

	slashIndex := strings.Index(resource, "/")

	if slashIndex > 0 {
		newResources := strings.Split(resource, "/")
		resource = newResources[0]
		subresource = newResources[1]
		group = "authentication.k8s.io"
	}

	// UID impersonation lives in authentication.k8s.io, unlike
	// users/groups/serviceaccounts which are core. Without the group the
	// review checks a core-group "uids" resource no RBAC rule grants.
	if resource == "uids" {
		group = "authentication.k8s.io"
	}

	return v1.SubjectAccessReviewSpec{
		User:   requester.GetName(),
		UID:    requester.GetUID(),
		Groups: requester.GetGroups(),
		Extra:  extras,

		ResourceAttributes: &v1.ResourceAttributes{
			Verb:        "impersonate",
			Group:       group,
			Resource:    resource,
			Subresource: subresource,
			Name:        name,
		},
	}
}
