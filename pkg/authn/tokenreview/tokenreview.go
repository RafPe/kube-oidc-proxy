// Copyright Jetstack Ltd. See LICENSE for details.

// Package tokenreview authenticates bearer tokens by submitting TokenReviews to
// the Kubernetes API server.
package tokenreview

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"sync"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	clientauthv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/utils/clock"

	"github.com/rafpe/kube-oidc-proxy/pkg/ctxerr"
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

// tokenCacheSize bounds the number of cached review results. Cache keys derive
// from attacker-supplied bearer tokens, so the cache evicts (LRU) rather than
// let a flood of unique invalid tokens grow it; 8192 entries hold a large
// cluster's live tokens for one TTL in a few megabytes.
const tokenCacheSize = 8192

// ErrCreateTokenReview is the one error class the authenticator New returns:
// every error from AuthenticateToken wraps it, whether the API server could
// not be reached, did not answer in time, or answered with a status error. It
// marks a dependency failure, not a verdict on the token (a refused token is
// ok=false with a nil error). The underlying error (including
// context.Canceled/DeadlineExceeded) is wrapped alongside it.
var ErrCreateTokenReview = errors.New("create TokenReview")

// liveReviewer submits a TokenReview to the API server for every call. New
// fronts it with a cachedReviewer unless Config switches the cache off.
type liveReviewer struct {
	// logger is the tokenreview-component logger every record this reviewer
	// emits goes through, so each carries component=tokenreview. The
	// per-request correlation id travels on the call's context instead, never
	// bound onto a logger, and Emit reads it from there.
	logger *slog.Logger

	client    clientauthv1.TokenReviewInterface
	audiences []string
	timeout   time.Duration

	// metrics receives the API-call and cache observations; nil records nothing.
	metrics *metrics.Recorder
}

var _ authenticator.Token = (*liveReviewer)(nil)

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

	// Metrics receives the API-call and cache observations. Optional: nil
	// records nothing.
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
// logger is the tokenreview-component logger; New panics when it is nil.
func New(client clientauthv1.TokenReviewInterface, cfg Config, logger *slog.Logger) authenticator.Token {
	if logger == nil {
		panic("tokenreview: nil logger")
	}

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

// newCachedReviewer builds the cache layer with an explicit entry cap and
// clock; both are parameters only so tests can exercise eviction and expiry
// cheaply and deterministically.
//
// Cache keys are an HMAC-SHA256, keyed with a per-instance random key, over
// the length-prefixed token and configured audiences (mirroring the upstream
// cache's keyFunc): tokens are never stored in memory as map keys, keys
// cannot be precomputed or length-extended, and two audience sets can never
// collide; each cache is also private to its reviewer.
func newCachedReviewer(reviewer *liveReviewer, successTTL, failureTTL time.Duration, size int, clk utilcache.Clock) *cachedReviewer {
	randomKey := make([]byte, 32)
	if _, err := rand.Read(randomKey); err != nil {
		panic(err) // rand.Read never fails
	}

	return &cachedReviewer{
		reviewer:   reviewer,
		successTTL: successTTL,
		failureTTL: failureTTL,
		cache:      utilcache.NewLRUExpireCacheWithClock(size, clk),
		hashPool: &sync.Pool{
			New: func() any {
				return hmac.New(sha256.New, randomKey)
			},
		},
	}
}

// cachedReviewer caches the delegate reviewer's results in a
// fixed-capacity LRU store. Entries past their TTL are dropped on lookup, and
// once the store holds tokenCacheSize entries every insertion evicts the
// least recently used one, so a flood of unique (attacker-controlled) tokens
// recycles the same fixed slots instead of growing memory.
type cachedReviewer struct {
	reviewer   *liveReviewer
	successTTL time.Duration
	failureTTL time.Duration

	cache    *utilcache.LRUExpireCache
	hashPool *sync.Pool
}

var _ authenticator.Token = (*cachedReviewer)(nil)

// cacheEntry is the cacheable subset of an AuthenticateToken result. Errors
// are deliberately unrepresentable: only definitive answers are cached.
type cacheEntry struct {
	resp *authenticator.Response
	ok   bool
}

func (c *cachedReviewer) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	key := cacheKey(c.hashPool, token, c.reviewer.audiences)

	if v, hit := c.cache.Get(key); hit {
		entry := v.(cacheEntry)
		c.recordCacheLookup(ctx, metrics.CacheHit, slog.Bool("authenticated", entry.ok))
		return entry.resp, entry.ok, nil
	}
	c.recordCacheLookup(ctx, metrics.CacheMiss)

	resp, ok, err := c.reviewer.AuthenticateToken(ctx, token)
	if err != nil {
		return nil, false, err
	}

	switch {
	case ok && c.successTTL > 0:
		c.cache.Add(key, cacheEntry{resp: resp, ok: true}, c.successTTL)
	case !ok && c.failureTTL > 0:
		c.cache.Add(key, cacheEntry{}, c.failureTTL)
	}

	return resp, ok, nil
}

// recordCacheLookup reports one cache consultation, as a record and as a
// metric.
func (c *cachedReviewer) recordCacheLookup(ctx context.Context, result metrics.CacheResult, attrs ...slog.Attr) {
	attrs = append([]slog.Attr{slog.String("cache_result", string(result))}, attrs...)
	logging.Emit(ctx, c.reviewer.logger, logging.EventCacheTokenReviewLookup, attrs...)
	c.reviewer.metrics.CacheLookup(metrics.ReviewTokenReview, result)
}

// cacheKey hashes the token and audiences into a cache key. Every component
// is length-prefixed so distinct (token, audiences) inputs can never encode
// to the same byte stream (e.g. token "x" with audience "yz" versus token
// "xy" with audience "z").
func cacheKey(hashPool *sync.Pool, token string, audiences []string) string {
	h := hashPool.Get().(hash.Hash)
	defer hashPool.Put(h)
	h.Reset()

	var b [8]byte
	writeLengthPrefixed(h, b[:], token)
	binary.BigEndian.PutUint64(b[:], uint64(len(audiences)))
	h.Write(b[:])
	for _, aud := range audiences {
		writeLengthPrefixed(h, b[:], aud)
	}

	return string(h.Sum(nil))
}

// writeLengthPrefixed writes s preceded by its length. b is a scratch buffer
// of at least 8 bytes.
func writeLengthPrefixed(h hash.Hash, b []byte, s string) {
	binary.BigEndian.PutUint64(b, uint64(len(s)))
	h.Write(b[:8])
	h.Write([]byte(s))
}

// AuthenticateToken implements authenticator.Token by submitting a
// TokenReview for the bearer token. It returns ok=false with a nil error when
// the API server answers but does not authenticate the token, and an error
// wrapping ErrCreateTokenReview when the review itself failed; callers must
// treat both as unauthenticated (fail closed).
//
// The reviewer records its own outcome: authn.tokenreview.completed for an
// answer, authn.tokenreview.failed for a review that got none.
func (r *liveReviewer) AuthenticateToken(requestCtx context.Context, token string) (*authenticator.Response, bool, error) {
	ctx, cancel := context.WithTimeout(requestCtx, r.timeout)
	defer cancel()

	start := time.Now()

	resp, err := r.client.Create(ctx, r.buildReview(token), metav1.CreateOptions{})
	// Observed at the one place the API server is called: the outcome is the
	// call's, not the caller's, so a cache hit or a fallback never counts.
	switch {
	case err != nil:
		r.metrics.ReviewRequest(metrics.ReviewTokenReview, metrics.ReviewOutcomeFor(err, false), time.Since(start))
		return nil, false, r.failed(requestCtx, fmt.Errorf("%w: %w", ErrCreateTokenReview, err))
	case len(resp.Status.Error) > 0:
		r.metrics.ReviewRequest(metrics.ReviewTokenReview, metrics.ReviewError, time.Since(start))
		return nil, false, r.failed(requestCtx, fmt.Errorf("%w: status error: %s", ErrCreateTokenReview, resp.Status.Error))
	}
	r.metrics.ReviewRequest(metrics.ReviewTokenReview, metrics.ReviewOutcomeFor(nil, resp.Status.Authenticated), time.Since(start))

	logging.Emit(ctx, r.logger, logging.EventAuthnTokenReviewCompleted,
		slog.Bool("authenticated", resp.Status.Authenticated),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()))

	if !resp.Status.Authenticated {
		return nil, false, nil
	}

	return &authenticator.Response{
		Audiences: authenticator.Audiences(resp.Status.Audiences),
		User:      userInfoFrom(resp.Status.User),
	}, true, nil
}

// failed emits authn.tokenreview.failed for err and returns it. requestCtx is
// the caller's context, not the one bounded by the review timeout: a review
// that failed because the client itself went away is a per-request condition
// at DEBUG, so a client cannot drive the ERROR stream by hanging up
// mid-request, while the reviewer's own timeout expiring is a dependency
// failure and stays an ERROR.
func (r *liveReviewer) failed(requestCtx context.Context, err error) error {
	reason, level := metrics.ReasonAuthenticationDependencyError, slog.LevelError
	if ctxerr.ClientGone(requestCtx, err) {
		reason, level = metrics.ReasonClientCanceled, slog.LevelDebug
	}
	logging.EmitLevel(requestCtx, r.logger, logging.EventAuthnTokenReviewFailed, level,
		slog.String("reason", string(reason)), logging.ErrAttr(err))
	return err
}

// userInfoFrom converts the TokenReview status identity into the
// authenticator's user.Info shape.
func userInfoFrom(ui authv1.UserInfo) user.Info {
	info := &user.DefaultInfo{
		Name:   ui.Username,
		UID:    ui.UID,
		Groups: ui.Groups,
	}
	if len(ui.Extra) > 0 {
		info.Extra = make(map[string][]string, len(ui.Extra))
		for k, v := range ui.Extra {
			info.Extra[k] = v
		}
	}
	return info
}

func (r *liveReviewer) buildReview(token string) *authv1.TokenReview {
	return &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: r.audiences,
		},
	}
}
