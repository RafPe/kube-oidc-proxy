// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

// reviewCall is one request's authorization questions: the context its
// reviews run on, which carries the shared SAR budget, the inbound request's
// own context, and the identity asking. The two contexts are kept apart
// because a review that fails with a context error must say whose deadline
// expired: the requester's, when the client went away, or the proxy's budget,
// when the API server did not answer in time.
type reviewCall struct {
	ctx       context.Context
	request   context.Context
	requester user.Info
}

// requesterGone reports whether the inbound request itself has finished.
func (c reviewCall) requesterGone() bool {
	return c.request.Err() != nil
}

// cachedCheck answers whether the caller may impersonate target. The
// decision comes from the cache when a definitive, unexpired one is present;
// otherwise a live SubjectAccessReview is submitted to the API server. A cache
// hit returns the same (allowed, nil) pair the live check produced, so callers
// build byte-identical *ImpersonationAuthError denials either way. Errors are
// never cached: a transient API-server failure fails only the requests that
// observed it.
func (s *SubjectAccessReview) cachedCheck(call reviewCall, target impersonationTarget) (bool, error) {
	spec := impersonationReviewSpec(target, call.requester)

	key, cacheable := s.cache.key(&spec)
	if !cacheable {
		s.recordCacheLookup(call.ctx, metrics.CacheBypass)
		return s.timedLiveCheck(call, target, false, &spec)
	}

	if allowed, ok := s.cache.get(key); ok {
		s.recordCacheLookup(call.ctx, metrics.CacheHit,
			slog.String("decision", string(metrics.DecisionFor(allowed))))
		return allowed, nil
	}
	s.recordCacheLookup(call.ctx, metrics.CacheMiss)

	return s.sharedLiveCheck(call, target, key, &spec)
}

// recordCacheLookup reports one decision-cache consultation, as a record and
// as a metric, so the two can never disagree about what the cache did.
func (s *SubjectAccessReview) recordCacheLookup(ctx context.Context, result metrics.CacheResult, attrs ...slog.Attr) {
	attrs = append([]slog.Attr{slog.String("cache_result", string(result))}, attrs...)
	logging.Emit(ctx, s.logger, logging.EventCacheSARLookup, attrs...)
	s.metrics.CacheLookup(metrics.ReviewSAR, result)
}

// timedLiveCheck runs one live check and records its outcome: a completed
// review carrying how long the caller waited and whether it shared another
// request's call, or a failure carrying the dependency error. Exactly one
// terminal record is emitted per authorization question a caller asks.
func (s *SubjectAccessReview) timedLiveCheck(call reviewCall, target impersonationTarget, coalesced bool, spec *v1.SubjectAccessReviewSpec) (bool, error) {
	start := time.Now()
	allowed, err := s.liveCheck(call.ctx, spec)
	s.observeLiveCheck(call, target, start, coalesced, allowed, err)
	return allowed, err
}

// observeLiveCheck emits the terminal record for one live check begun at start.
// A failure is classified before it is recorded, and a context error is not
// self-explanatory: the review context carries both the requester's deadline
// and the proxy's own SAR budget. When the requester is the one that went away
// — a client disconnect, or its own deadline — the failure is a per-request
// condition at DEBUG, so a client cannot drive the ERROR stream simply by
// hanging up mid-request. When the requester is still waiting, the deadline
// that expired is the proxy's budget, which means the API server did not
// answer in time: that is a dependency failure and stays an ERROR.
func (s *SubjectAccessReview) observeLiveCheck(call reviewCall, target impersonationTarget, start time.Time, coalesced, allowed bool, err error) {
	if err != nil {
		reason, level, logged := metrics.ReasonAuthorizationDependencyError, slog.LevelError, err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if call.requesterGone() {
				reason, level = metrics.ReasonClientCanceled, slog.LevelDebug
			} else {
				logged = fmt.Errorf("subject access review timed out after %s: %w", s.sarTimeout, err)
			}
		}
		logging.EmitLevel(call.ctx, s.logger, logging.EventAuthzSARFailed, level,
			slog.String("reason", string(reason)),
			logging.ErrAttr(logged))
		return
	}
	logging.Emit(call.ctx, s.logger, logging.EventAuthzSARCompleted,
		slog.String("decision", string(metrics.DecisionFor(allowed))),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		slog.Bool("request_coalesced", coalesced),
		slog.String("target_kind", string(target.kind)))
}

// sharedLiveCheck performs a live check deduplicated across concurrent callers
// asking the identical authorization question, caching the resulting decision.
// The winning caller's context governs the shared call, so a waiter whose
// flight fails with a context error not its own retries with a direct check
// rather than inheriting another request's cancellation.
func (s *SubjectAccessReview) sharedLiveCheck(call reviewCall, target impersonationTarget, key string, spec *v1.SubjectAccessReviewSpec) (bool, error) {
	ctx := call.ctx
	start := time.Now()

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
		s.observeLiveCheck(call, target, start, false, false, err)
		return false, err
	case res := <-ch:
		if res.Err != nil {
			if res.Shared && ctx.Err() == nil &&
				(errors.Is(res.Err, context.Canceled) || errors.Is(res.Err, context.DeadlineExceeded)) {
				// The foreign flight's failure was not ours to report; the retry
				// below emits this caller's one terminal record.
				return s.timedLiveCheck(call, target, false, spec)
			}
			s.observeLiveCheck(call, target, start, res.Shared, false, res.Err)
			return false, res.Err
		}
		allowed := res.Val.(bool)
		s.observeLiveCheck(call, target, start, res.Shared, allowed, nil)
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
func impersonationReviewSpec(target impersonationTarget, requester user.Info) v1.SubjectAccessReviewSpec {
	extras := make(map[string]v1.ExtraValue, len(requester.GetExtra()))
	for key, value := range requester.GetExtra() {
		extras[key] = value
	}

	return v1.SubjectAccessReviewSpec{
		User:   requester.GetName(),
		UID:    requester.GetUID(),
		Groups: requester.GetGroups(),
		Extra:  extras,

		ResourceAttributes: &v1.ResourceAttributes{
			Verb:        impersonateVerb,
			Group:       target.group,
			Resource:    target.resource,
			Subresource: target.subresource,
			Name:        target.name,
		},
	}
}
