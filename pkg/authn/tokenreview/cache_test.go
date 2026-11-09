// Copyright Jetstack Ltd. See LICENSE for details.
package tokenreview

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/tokenreview/fake"
)

// TestWithCache exercises the cached reviewer end to end against a counting
// fake: which results are served from cache, which always go back to the API
// server, and how the TTLs bound reuse.
func TestWithCache(t *testing.T) {
	type step struct {
		token   string
		advance time.Duration
		expOK   bool
		expErr  bool
	}

	tests := map[string]struct {
		successTTL time.Duration
		failureTTL time.Duration

		// create serves the fake API server. call is 1-based.
		create func(call int64, review *authv1.TokenReview) (*authv1.TokenReview, error)

		steps    []step
		expCalls int64
	}{
		"a cache hit avoids a second apiserver call": {
			successTTL: 10 * time.Second,
			failureTTL: 10 * time.Second,
			create: func(int64, *authv1.TokenReview) (*authv1.TokenReview, error) {
				return authenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: true},
				{token: "token-a", expOK: true},
			},
			expCalls: 1,
		},

		"distinct tokens get distinct cache entries": {
			successTTL: 10 * time.Second,
			failureTTL: 10 * time.Second,
			create: func(_ int64, review *authv1.TokenReview) (*authv1.TokenReview, error) {
				if review.Spec.Token == "token-a" {
					return authenticatedReview(), nil
				}
				return unauthenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: true},
				{token: "token-b", expOK: false},
				{token: "token-a", expOK: true},
				{token: "token-b", expOK: false},
			},
			expCalls: 2,
		},

		"error results are not cached and are retried on the next request": {
			successTTL: 10 * time.Second,
			failureTTL: 10 * time.Second,
			create: func(call int64, _ *authv1.TokenReview) (*authv1.TokenReview, error) {
				if call == 1 {
					return nil, errors.New("apiserver unreachable")
				}
				return authenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: false, expErr: true},
				{token: "token-a", expOK: true},
			},
			expCalls: 2,
		},

		"unauthenticated results are cached for the failure TTL": {
			successTTL: 10 * time.Second,
			failureTTL: 10 * time.Second,
			create: func(int64, *authv1.TokenReview) (*authv1.TokenReview, error) {
				return unauthenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: false},
				{token: "token-a", expOK: false},
			},
			expCalls: 1,
		},

		"success TTL expiry forces a fresh review": {
			successTTL: 20 * time.Millisecond,
			failureTTL: 10 * time.Second,
			create: func(int64, *authv1.TokenReview) (*authv1.TokenReview, error) {
				return authenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: true},
				{token: "token-a", advance: 100 * time.Millisecond, expOK: true},
			},
			expCalls: 2,
		},

		"zero failure TTL leaves unauthenticated results uncached": {
			successTTL: 10 * time.Second,
			failureTTL: 0,
			create: func(int64, *authv1.TokenReview) (*authv1.TokenReview, error) {
				return unauthenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: false},
				{token: "token-a", expOK: false},
			},
			expCalls: 2,
		},

		"zero TTLs bypass the cache entirely": {
			successTTL: 0,
			failureTTL: 0,
			create: func(int64, *authv1.TokenReview) (*authv1.TokenReview, error) {
				return authenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: true},
				{token: "token-a", expOK: true},
			},
			expCalls: 2,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			reviewer := newReviewer(&fake.FakeReviewer{
				CreateFn: func(review *authv1.TokenReview) (*authv1.TokenReview, error) {
					return test.create(calls.Add(1), review)
				},
			}, Config{}, discardLogger)

			clock := &fakeClock{now: time.Unix(1000, 0)}
			var cached authenticator.Token = reviewer
			if test.successTTL > 0 || test.failureTTL > 0 {
				cached = newCachedTokenReview(reviewer, test.successTTL, test.failureTTL, tokenCacheSize, clock)
			}

			for i, s := range test.steps {
				clock.advance(s.advance)

				_, ok, err := cached.AuthenticateToken(testRequestContext(), s.token)
				if s.expErr != (err != nil) {
					t.Fatalf("step %d: unexpected error state, expErr=%t got=%v", i, s.expErr, err)
				}
				if s.expOK != ok {
					t.Fatalf("step %d: unexpected ok, exp=%t got=%t", i, s.expOK, ok)
				}
			}

			if got := calls.Load(); got != test.expCalls {
				t.Errorf("unexpected number of apiserver calls, exp=%d got=%d", test.expCalls, got)
			}
		})
	}
}

// TestWithCacheZeroTTLsReturnsBareReviewer pins that disabling both TTLs keeps
// the exact pre-cache behaviour: no cache layer at all.
func TestWithCacheZeroTTLsReturnsBareReviewer(t *testing.T) {
	reviewer := newReviewer(fake.New(), Config{}, discardLogger)
	if got := withCache(reviewer, 0, 0); got != reviewer {
		t.Errorf("expected the bare reviewer back for zero TTLs, got %T", got)
	}
}

// TestCachedReviewHonoursCallerCancellation pins that enabling the cache does
// not detach reviews from the inbound request: cancelling the caller's context
// must cancel the in-flight TokenReview and surface the cancellation error.
func TestCachedReviewHonoursCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(testRequestContext())
	defer cancel()

	reviewer := newReviewer(&fake.FakeReviewer{
		CreateCtxFn: func(reviewCtx context.Context, _ *authv1.TokenReview) (*authv1.TokenReview, error) {
			// Cancel the inbound request while its review is in flight;
			// the review's context must observe the cancellation.
			cancel()
			select {
			case <-reviewCtx.Done():
				return nil, reviewCtx.Err()
			case <-time.After(5 * time.Second):
				return authenticatedReview(), nil
			}
		},
	}, Config{}, discardLogger)

	cached := withCache(reviewer, 10*time.Second, 10*time.Second)

	start := time.Now()
	resp, ok, err := cached.AuthenticateToken(ctx, "token-a")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected the caller's cancellation to reach the review, got err=%v", err)
	}
	if ok || resp != nil {
		t.Errorf("expected a failed review on cancellation, got ok=%t resp=%#v", ok, resp)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("cancellation did not propagate promptly, review returned after %s", elapsed)
	}
}

// TestCachedReviewHonoursTimeoutAboveThirtySeconds pins that the configured
// review timeout is applied in full when the cache is enabled. The upstream
// kube-apiserver token cache would cap it at a hardcoded 30s; this cache must
// not.
func TestCachedReviewHonoursTimeoutAboveThirtySeconds(t *testing.T) {
	const configured = 45 * time.Second

	var gotDeadline time.Time
	var hadDeadline bool
	reviewer := newReviewer(&fake.FakeReviewer{
		CreateCtxFn: func(reviewCtx context.Context, _ *authv1.TokenReview) (*authv1.TokenReview, error) {
			gotDeadline, hadDeadline = reviewCtx.Deadline()
			return authenticatedReview(), nil
		},
	}, Config{Timeout: configured}, discardLogger)

	cached := withCache(reviewer, 10*time.Second, 10*time.Second)

	before := time.Now()
	if _, ok, err := cached.AuthenticateToken(testRequestContext(), "token-a"); err != nil || !ok {
		t.Fatalf("unexpected review result, ok=%t err=%v", ok, err)
	}

	if !hadDeadline {
		t.Fatal("expected the review context to carry the configured deadline")
	}
	if remaining := gotDeadline.Sub(before); remaining <= 30*time.Second {
		t.Errorf("configured timeout was capped: review deadline only %s away, want ~%s", remaining, configured)
	}
}

// TestCachedReviewSeparatesAudienceSets pins the security invariant that the
// same token reviewed under different configured audience sets can never share
// a cache entry.
func TestCachedReviewSeparatesAudienceSets(t *testing.T) {
	// One counting fake serves both reviewers and keys its answer off the
	// audiences in the review spec: aud-1 authenticates, anything else does
	// not. A cross-audience cache collision would surface as a wrong result
	// or a missing apiserver call.
	var calls atomic.Int64
	requester := &fake.FakeReviewer{
		CreateFn: func(review *authv1.TokenReview) (*authv1.TokenReview, error) {
			calls.Add(1)
			if reflect.DeepEqual(review.Spec.Audiences, []string{"aud-1"}) {
				return authenticatedReview(), nil
			}
			return unauthenticatedReview(), nil
		},
	}

	cachedAud1 := withCache(newReviewer(requester, Config{Audiences: []string{"aud-1"}}, discardLogger),
		10*time.Second, 10*time.Second)
	cachedAud2 := withCache(newReviewer(requester, Config{Audiences: []string{"aud-2"}}, discardLogger),
		10*time.Second, 10*time.Second)

	for i := range 2 {
		if _, ok, err := cachedAud1.AuthenticateToken(testRequestContext(), "token-a"); err != nil || !ok {
			t.Fatalf("round %d: unexpected aud-1 result, ok=%t err=%v", i, ok, err)
		}
		if _, ok, err := cachedAud2.AuthenticateToken(testRequestContext(), "token-a"); err != nil || ok {
			t.Fatalf("round %d: aud-2 review must not reuse the aud-1 cached success, ok=%t err=%v", i, ok, err)
		}
	}

	// One review per audience set; the second round of each was a cache hit
	// on its own entry.
	if got := calls.Load(); got != 2 {
		t.Errorf("unexpected number of apiserver calls, exp=2 got=%d", got)
	}
}

// TestCacheKey pins the collision resistance of the key derivation: distinct
// (token, audiences) inputs must map to distinct keys, including the
// length-prefix ambiguities a naive concatenation would collapse.
func TestCacheKey(t *testing.T) {
	pool := &sync.Pool{
		New: func() any {
			return hmac.New(sha256.New, []byte("fixed-test-key"))
		},
	}

	base := cacheKey(pool, "token", []string{"aud-1"})

	if got := cacheKey(pool, "token", []string{"aud-1"}); got != base {
		t.Error("equal inputs must produce equal keys")
	}

	distinct := map[string]string{
		"different token":                 cacheKey(pool, "token-b", []string{"aud-1"}),
		"different audience":              cacheKey(pool, "token", []string{"aud-2"}),
		"no audiences":                    cacheKey(pool, "token", nil),
		"split audience list":             cacheKey(pool, "token", []string{"aud", "-1"}),
		"token/audience boundary shifted": cacheKey(pool, "tokenaud-1", nil),
	}
	for name, key := range distinct {
		if key == base {
			t.Errorf("%s must not collide with the base key", name)
		}
	}
}

// TestCachedReviewBoundsEntryCount pins that the cache enforces a hard entry
// cap with LRU eviction: a flood of unique (attacker-controlled) tokens must
// recycle the fixed slots rather than each pin memory for the full TTL.
func TestCachedReviewBoundsEntryCount(t *testing.T) {
	const extra = 8

	var calls atomic.Int64
	reviewer := newReviewer(&fake.FakeReviewer{
		CreateFn: func(*authv1.TokenReview) (*authv1.TokenReview, error) {
			calls.Add(1)
			return unauthenticatedReview(), nil
		},
	}, Config{}, discardLogger)

	cached := withCache(reviewer, time.Hour, time.Hour).(*cachedTokenReview)

	for i := range tokenCacheSize + extra {
		token := fmt.Sprintf("unique-token-%d", i)
		if _, ok, err := cached.AuthenticateToken(testRequestContext(), token); err != nil || ok {
			t.Fatalf("token %d: unexpected result, ok=%t err=%v", i, ok, err)
		}
	}

	if got := len(cached.cache.Keys()); got != tokenCacheSize {
		t.Errorf("cache size must stay at the cap after cap+%d inserts, exp=%d got=%d",
			extra, tokenCacheSize, got)
	}

	// The oldest tokens must have been evicted: reviewing the first one again
	// reaches the apiserver instead of the cache, despite its unexpired TTL...
	before := calls.Load()
	if _, _, err := cached.AuthenticateToken(testRequestContext(), "unique-token-0"); err != nil {
		t.Fatalf("unexpected error re-reviewing the evicted token: %v", err)
	}
	if got := calls.Load(); got != before+1 {
		t.Errorf("expected the oldest token to have been evicted and re-reviewed live, calls exp=%d got=%d",
			before+1, got)
	}

	// ...while the most recently inserted token is still served from cache.
	last := fmt.Sprintf("unique-token-%d", tokenCacheSize+extra-1)
	before = calls.Load()
	if _, _, err := cached.AuthenticateToken(testRequestContext(), last); err != nil {
		t.Fatalf("unexpected error re-reviewing the cached token: %v", err)
	}
	if got := calls.Load(); got != before {
		t.Errorf("expected the most recent token to still be cached, calls exp=%d got=%d", before, got)
	}
}

// TestCachedReviewConcurrentMissesRunIndependently pins the documented
// no-singleflight contract: concurrent misses for the same token each run
// their own live review, exactly as every request did before caching existed.
// The fake only answers once both reviews are in flight, so any collapsing of
// the two misses into one review fails the test.
func TestCachedReviewConcurrentMissesRunIndependently(t *testing.T) {
	bothInFlight := make(chan struct{})

	var calls atomic.Int64
	reviewer := newReviewer(&fake.FakeReviewer{
		CreateCtxFn: func(context.Context, *authv1.TokenReview) (*authv1.TokenReview, error) {
			if calls.Add(1) == 2 {
				close(bothInFlight)
			}
			select {
			case <-bothInFlight:
				return authenticatedReview(), nil
			case <-time.After(5 * time.Second):
				return nil, errors.New("second review never started: concurrent misses were collapsed")
			}
		},
	}, Config{}, discardLogger)

	cached := withCache(reviewer, 10*time.Second, 10*time.Second)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	oks := make([]bool, 2)
	for i := range 2 {
		wg.Go(func() {
			_, oks[i], errs[i] = cached.AuthenticateToken(testRequestContext(), "token-a")
		})
	}
	wg.Wait()

	for i := range 2 {
		if errs[i] != nil || !oks[i] {
			t.Errorf("request %d: unexpected result, ok=%t err=%v", i, oks[i], errs[i])
		}
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("expected two live reviews for two concurrent misses, got=%d", got)
	}
}

// TestCachedReviewSendsConfiguredAudiences verifies the audiences configured
// on the reviewer still reach the API server in the TokenReview spec when the
// cache wrapper is in place.
func TestCachedReviewSendsConfiguredAudiences(t *testing.T) {
	audiences := []string{"aud-1", "aud-2"}

	var gotAudiences []string
	reviewer := newReviewer(&fake.FakeReviewer{
		CreateFn: func(review *authv1.TokenReview) (*authv1.TokenReview, error) {
			gotAudiences = review.Spec.Audiences
			return authenticatedReview(), nil
		},
	}, Config{Audiences: audiences}, discardLogger)

	cached := withCache(reviewer, 10*time.Second, 10*time.Second)

	if _, ok, err := cached.AuthenticateToken(testRequestContext(), "token-a"); err != nil || !ok {
		t.Fatalf("unexpected review result, ok=%t err=%v", ok, err)
	}

	if !reflect.DeepEqual(audiences, gotAudiences) {
		t.Errorf("unexpected audiences on the review, exp=%v got=%v", audiences, gotAudiences)
	}
}

// fakeClock is a settable clock for the cache's expiry, so a TTL test advances
// time instead of sleeping on the wall clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
