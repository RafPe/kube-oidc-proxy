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
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
)

// reviewCall is one request's authorization questions: the context its
// reviews run on, which carries the shared SAR budget, the inbound request's
// own context, and the identity asking. The two contexts are kept apart
// because a review that fails with a context error must say whose deadline
// expired: the requester's, when the client went away, or the proxy's budget,
// when the API server did not answer in time. reqctx.ClientGone tells them
// apart.
type reviewCall struct {
	ctx        context.Context
	requestCtx context.Context
	requester  user.Info
}

// liveResult is how one caller's live check ended: the decision or the
// dependency error, and whether the caller joined another request's flight
// rather than running the review itself.
type liveResult struct {
	allowed   bool
	err       error
	coalesced bool
}

// cachedCheck answers whether the caller may impersonate target. The
// decision comes from the cache when a definitive, unexpired one is present;
// otherwise a live SubjectAccessReview is submitted to the API server. With
// the cache switched off no lookup is recorded, as for the TokenReview cache;
// a lookup is a bypass only when the spec is too large to cache. A cache
// hit returns the same (allowed, nil) pair the live check produced, so callers
// build byte-identical *ImpersonationAuthError denials either way. Errors are
// never cached: a transient API-server failure fails only the requests that
// observed it.
func (a *Authorizer) cachedCheck(call reviewCall, target impersonationTarget) (bool, error) {
	spec := impersonationReviewSpec(target, call.requester)
	if a.cache == nil {
		return a.timedLiveCheck(call, target, &spec)
	}

	key, cacheable := a.cache.key(&spec)
	if !cacheable {
		a.recordCacheLookup(call.ctx, metrics.CacheBypass)
		return a.timedLiveCheck(call, target, &spec)
	}

	if allowed, ok := a.cache.get(key); ok {
		a.recordCacheLookup(call.ctx, metrics.CacheHit,
			slog.String("decision", string(metrics.DecisionFor(allowed))))
		return allowed, nil
	}
	a.recordCacheLookup(call.ctx, metrics.CacheMiss)

	return a.sharedLiveCheck(call, target, key, &spec)
}

// recordCacheLookup reports one decision-cache consultation, as a record and
// as a metric, so the two can never disagree about what the cache did.
func (a *Authorizer) recordCacheLookup(ctx context.Context, result metrics.CacheResult, attrs ...slog.Attr) {
	attrs = append([]slog.Attr{slog.String("cache_result", string(result))}, attrs...)
	logging.Emit(ctx, a.logger, logging.EventCacheSARLookup, attrs...)
	a.metrics.CacheLookup(metrics.ReviewSAR, result)
}

// timedLiveCheck runs one live check of the caller's own and records its
// outcome: a completed review carrying how long the caller waited, or a
// failure carrying the dependency error. Exactly one terminal record is
// emitted per authorization question a caller asks.
func (a *Authorizer) timedLiveCheck(call reviewCall, target impersonationTarget, spec *v1.SubjectAccessReviewSpec) (bool, error) {
	start := time.Now()
	allowed, err := a.liveCheck(call.ctx, spec)
	a.observeLiveCheck(call, target, start, liveResult{allowed: allowed, err: err})
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
func (a *Authorizer) observeLiveCheck(call reviewCall, target impersonationTarget, start time.Time, res liveResult) {
	if err := res.err; err != nil {
		reason, level, logged := metrics.ReasonAuthorizationDependencyError, slog.LevelError, err
		switch {
		case reqctx.ClientGone(call.requestCtx, err):
			reason, level = metrics.ReasonClientCanceled, slog.LevelDebug
		case isContextError(err):
			logged = fmt.Errorf("subject access review timed out after %s: %w", a.timeout, err)
		}
		logging.EmitLevel(call.ctx, a.logger, logging.EventAuthzSARFailed, level,
			slog.String("reason", string(reason)),
			logging.ErrAttr(logged))
		return
	}
	logging.Emit(call.ctx, a.logger, logging.EventAuthzSARCompleted,
		slog.String("decision", string(metrics.DecisionFor(res.allowed))),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		slog.Bool("request_coalesced", res.coalesced),
		slog.String("target_kind", string(target.kind)))
}

// sharedLiveCheck performs a live check deduplicated across concurrent callers
// asking the identical authorization question, caching the resulting decision.
//
// Exactly one caller leads a flight: its closure runs the review on its own
// context. Every other caller joins and is reported as coalesced. The leader
// is told apart by having run the closure, not by singleflight's Result.Shared,
// which is set on every caller's result, the leader's included, whenever
// anyone joined. A joiner whose flight fails with a context error not its own
// retries with a check of its own rather than inheriting another request's
// cancellation; the leader's context error is its own and is reported as is.
func (a *Authorizer) sharedLiveCheck(call reviewCall, target impersonationTarget, key string, spec *v1.SubjectAccessReviewSpec) (bool, error) {
	ctx := call.ctx
	start := time.Now()

	// led is written by the closure, which only the leader's flight runs, and
	// read only after the flight's result is received: singleflight sends the
	// result after the closure returns, so the receive orders the two.
	led := false
	ch := a.flight.DoChan(key, func() (any, error) {
		led = true
		allowed, err := a.liveCheck(ctx, spec)
		if err != nil {
			return false, err
		}
		a.cache.put(key, allowed)
		return allowed, nil
	})

	select {
	case <-ctx.Done():
		// Our own request is done; do not wait on the shared flight.
		err := fmt.Errorf("%w: %w", ErrCreateSubjectAccessReview, ctx.Err())
		a.observeLiveCheck(call, target, start, liveResult{err: err})
		return false, err
	case res := <-ch:
		coalesced := !led
		if res.Err != nil {
			if coalesced && ctx.Err() == nil && isContextError(res.Err) {
				// The leader's failure was not ours to report; the retry below
				// emits this caller's one terminal record.
				return a.timedLiveCheck(call, target, spec)
			}
			a.observeLiveCheck(call, target, start, liveResult{err: res.Err, coalesced: coalesced})
			return false, res.Err
		}
		allowed := res.Val.(bool)
		a.observeLiveCheck(call, target, start, liveResult{allowed: allowed, coalesced: coalesced})
		return allowed, nil
	}
}

// isContextError reports whether err is a cancellation or an expired deadline,
// the failures whose owner has to be worked out before they are reported.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// liveCheck submits spec to the API server as a SubjectAccessReview and
// reports whether it allowed the request. It is the only place the API server
// is called, so it is where the review API-call metric is observed: a caller
// served by the cache or by a coalesced in-flight call never reaches here.
func (a *Authorizer) liveCheck(ctx context.Context, spec *v1.SubjectAccessReviewSpec) (bool, error) {
	clusterSubjectAccessReview := v1.SubjectAccessReview{Spec: *spec}

	start := time.Now()
	reviewResult, err := a.client.Create(ctx, &clusterSubjectAccessReview, metav1.CreateOptions{})
	allowed := err == nil && reviewResult.Status.Allowed
	a.metrics.ReviewRequest(metrics.ReviewSAR, metrics.ReviewOutcomeFor(err, allowed), time.Since(start))
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
			Namespace:   target.namespace,
			Group:       target.group,
			Resource:    target.resource,
			Subresource: target.subresource,
			Name:        target.name,
		},
	}
}
