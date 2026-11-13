// Copyright Jetstack Ltd. See LICENSE for details.

// Package tokenreview authenticates bearer tokens by submitting TokenReviews to
// the Kubernetes API server.
package tokenreview

import (
	"errors"
	"log/slog"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	clientauthv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/utils/clock"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

// The defaults the --token-passthrough-* flags start from. DefaultTimeout is
// also what a zero Config.Timeout means; the cache TTLs have no such fallback,
// because a zero TTL is how that class of caching is switched off.
const (
	DefaultTimeout         = 10 * time.Second
	DefaultSuccessCacheTTL = 10 * time.Second
	DefaultFailureCacheTTL = 10 * time.Second
)

// ErrCreateTokenReview is the one error class the authenticator New returns:
// every error from AuthenticateToken wraps it, whether the API server could
// not be reached, did not answer in time, or answered with a status error. It
// marks a dependency failure, not a verdict on the token (a refused token is
// ok=false with a nil error). The underlying error (including
// context.Canceled/DeadlineExceeded) is wrapped alongside it.
var ErrCreateTokenReview = errors.New("create TokenReview")

// Config is the operator-facing configuration of the token reviewer.
type Config struct {
	// Audiences are the audiences the reviewed token must be valid for.
	Audiences []string

	// Timeout bounds one TokenReview call; zero or negative means
	// DefaultTimeout.
	Timeout time.Duration

	// SuccessCacheTTL and FailureCacheTTL bound how long an authenticated or
	// unauthenticated answer is reused. Zero disables that class of caching,
	// and both zero switch the cache off. See New for the trade-off.
	SuccessCacheTTL time.Duration
	FailureCacheTTL time.Duration

	// Metrics receives the API-call and cache observations. Optional; see
	// package metrics.
	Metrics *metrics.Recorder
}

// New returns the authenticator that passes a bearer token through to the API
// server's TokenReview, with the result cache cfg asks for in front of it.
//
// Authenticated reviews are cached for cfg.SuccessCacheTTL and unauthenticated
// ones for cfg.FailureCacheTTL. Errors (API server unreachable, timeout,
// status error) are never cached, so a transient failure is retried on the
// next request and the path stays fail-closed. With both TTLs zero or
// negative the cache is switched off: the uncached reviewer is returned, every
// request runs its own TokenReview, and no cache lookup is recorded.
//
// A cache miss runs the TokenReview on the caller's own context, so the
// configured review timeout applies in full (including values above 30s) and
// cancelling the inbound request cancels its in-flight review. The deliberate
// trade-off is that concurrent misses for one token are not collapsed into a
// single review: each runs its own, so the cache only ever subtracts load.
// (The upstream kube-apiserver token cache deduplicates via singleflight
// instead, but pays for it by running lookups on a detached context with a
// hardcoded 30s cap, which would silently truncate longer configured timeouts
// and detach client cancellation.)
//
// Security: a cached success outlives token revocation for up to
// SuccessCacheTTL, so a token deleted or invalidated at the API server may
// still pass through this proxy until its cache entry expires. Keep it small;
// the kube-apiserver's own precedent is 10s.
//
// logger is the tokenreview-component logger.
func New(client clientauthv1.TokenReviewInterface, cfg Config, logger *slog.Logger) authenticator.Token {
	logging.RequireLogger(logger, "tokenreview")

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	reviewer := &liveReviewer{
		logger:    logger,
		client:    client,
		audiences: cfg.Audiences,
		timeout:   timeout,
		metrics:   cfg.Metrics,
	}

	if cfg.SuccessCacheTTL <= 0 && cfg.FailureCacheTTL <= 0 {
		return reviewer
	}
	return newCachedReviewer(reviewer, cfg.SuccessCacheTTL, cfg.FailureCacheTTL, tokenCacheSize, clock.RealClock{})
}
