// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	azv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/authentication/user"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

// fakeClock drives the decision cache's notion of time so TTL expiry can be
// exercised deterministically.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fnReviewer counts SAR Create calls and delegates the decision to a swappable
// function, letting tests simulate RBAC changes and transient API errors
// between calls.
type fnReviewer struct {
	calls atomic.Int64

	mu sync.Mutex
	fn func(*azv1.SubjectAccessReview) (*azv1.SubjectAccessReview, error)
}

func (r *fnReviewer) set(fn func(*azv1.SubjectAccessReview) (*azv1.SubjectAccessReview, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fn = fn
}

func (r *fnReviewer) Create(_ context.Context, req *azv1.SubjectAccessReview, _ metav1.CreateOptions) (*azv1.SubjectAccessReview, error) {
	r.calls.Add(1)
	r.mu.Lock()
	fn := r.fn
	r.mu.Unlock()
	return fn(req)
}

func allowAll(req *azv1.SubjectAccessReview) (*azv1.SubjectAccessReview, error) {
	req.Status = azv1.SubjectAccessReviewStatus{Allowed: true}
	return req, nil
}

func denyAll(req *azv1.SubjectAccessReview) (*azv1.SubjectAccessReview, error) {
	req.Status = azv1.SubjectAccessReviewStatus{Allowed: false}
	return req, nil
}

func failWith(err error) func(*azv1.SubjectAccessReview) (*azv1.SubjectAccessReview, error) {
	return func(*azv1.SubjectAccessReview) (*azv1.SubjectAccessReview, error) {
		return nil, err
	}
}

// newCachedSAR builds a SubjectAccessReview whose decision cache runs on the
// supplied clock, bypassing New only to inject deterministic time.
func newCachedSAR(r clientazv1.SubjectAccessReviewInterface, allowTTL, denyTTL time.Duration, clk utilcache.Clock) *Authorizer {
	return &Authorizer{
		logger:          slog.New(slog.DiscardHandler),
		client:          r,
		timeout:         DefaultTimeout,
		maxHeaderValues: DefaultMaxHeaderValues,
		cache:           newDecisionCache(allowTTL, denyTTL, decisionCacheSize, clk),
	}
}

// impersonateUserRequest returns a fresh request carrying a single
// Impersonate-User header. A new request is needed per check because a
// successful check strips the impersonation headers from the request.
func impersonateUserRequest(name string) *http.Request {
	h := http.Header{}
	h.Set("Impersonate-User", name)
	return (&http.Request{Header: h}).WithContext(testRequestContext())
}

func cacheTestRequester() *user.DefaultInfo {
	return &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}
}

// TestCacheAllowHitAndExpiry verifies an allowed decision is served from the
// cache for its TTL and re-checked live once the TTL elapses.
func TestCacheAllowHitAndExpiry(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &fnReviewer{}
	reviewer.set(allowAll)
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	for i := 0; i < 3; i++ {
		_, target, err := sar.ConsumeImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
		if err != nil {
			t.Fatalf("check %d: unexpected error: %v", i, err)
		}
		if target == nil || target.GetName() != "bob" {
			t.Fatalf("check %d: target = %+v, want user bob", i, target)
		}
	}
	if got := reviewer.calls.Load(); got != 1 {
		t.Errorf("SAR Create ran %d times for 3 identical allowed checks, want 1", got)
	}

	clk.Advance(11 * time.Second)

	if _, _, err := sar.ConsumeImpersonation(impersonateUserRequest("bob"), cacheTestRequester()); err != nil {
		t.Fatalf("post-expiry check: unexpected error: %v", err)
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times after allow TTL expiry, want 2 (expired entry must be re-checked)", got)
	}
}

// TestCacheDenyThenAllowAfterRBACChange simulates an RBAC edit granting a
// previously denied impersonation: while the deny TTL holds, the cached denial
// is returned byte-identically to the live one; once it expires the new allow
// is observed.
func TestCacheDenyThenAllowAfterRBACChange(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &fnReviewer{}
	reviewer.set(denyAll)
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	wantDenial := ImpersonationAuthError{Requester: "mmosley", Kind: TargetUser, Target: "bob"}

	_, target, err := sar.ConsumeImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
	if target != nil {
		t.Fatalf("live deny: target = %+v, want nil", target)
	}
	var live *ImpersonationAuthError
	if !errors.As(err, &live) || *live != wantDenial {
		t.Fatalf("live deny: error = %v, want %v", err, &wantDenial)
	}
	if !errors.Is(err, ErrImpersonationNotAllowed) {
		t.Fatalf("live deny: error = %v, want errors.Is(ErrImpersonationNotAllowed)", err)
	}

	// RBAC changes: the reviewer would now allow, but the cached denial holds.
	reviewer.set(allowAll)

	_, target, err = sar.ConsumeImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
	if target != nil {
		t.Fatalf("cached deny: target = %+v, want nil", target)
	}
	var cached *ImpersonationAuthError
	if !errors.As(err, &cached) || *cached != *live {
		t.Fatalf("cached deny: error = %v, want the identical denial %v", err, live)
	}
	if !errors.Is(err, ErrImpersonationNotAllowed) {
		t.Fatalf("cached deny: error = %v, want errors.Is(ErrImpersonationNotAllowed)", err)
	}
	if got := reviewer.calls.Load(); got != 1 {
		t.Errorf("SAR Create ran %d times while the deny TTL held, want 1", got)
	}

	clk.Advance(31 * time.Second)

	_, target, err = sar.ConsumeImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
	if err != nil {
		t.Fatalf("post-expiry check: unexpected error: %v", err)
	}
	if target == nil || target.GetName() != "bob" {
		t.Fatalf("post-expiry check: target = %+v, want user bob (new RBAC grant must be honoured)", target)
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times after deny TTL expiry, want 2", got)
	}
}

// TestCacheDenyTTLZeroRechecksImmediately verifies that a zero deny TTL keeps
// denials uncached so an RBAC grant is honoured on the very next request, even
// with allow caching enabled.
func TestCacheDenyTTLZeroRechecksImmediately(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &fnReviewer{}
	reviewer.set(denyAll)
	sar := newCachedSAR(reviewer, 10*time.Second, 0, clk)

	if _, _, err := sar.ConsumeImpersonation(impersonateUserRequest("bob"), cacheTestRequester()); !errors.Is(err, ErrImpersonationNotAllowed) {
		t.Fatalf("first check: error = %v, want denial", err)
	}

	reviewer.set(allowAll)

	_, target, err := sar.ConsumeImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
	if err != nil || target == nil || target.GetName() != "bob" {
		t.Fatalf("second check: target = %+v, err = %v, want immediate allow (denials must not be cached with TTL 0)", target, err)
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times, want 2", got)
	}
}

// TestErrorsNeverCached verifies a transient API-server failure is neither
// served from the cache nor turned into a cached denial.
func TestErrorsNeverCached(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	transient := errors.New("apiserver unavailable")
	reviewer := &fnReviewer{}
	reviewer.set(failWith(transient))
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	for i := 0; i < 2; i++ {
		_, _, err := sar.ConsumeImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
		if !errors.Is(err, ErrCreateSubjectAccessReview) || !errors.Is(err, transient) {
			t.Fatalf("check %d: error = %v, want the wrapped transient error", i, err)
		}
		if errors.Is(err, ErrImpersonationNotAllowed) {
			t.Fatalf("check %d: transient error classified as a denial: %v", i, err)
		}
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Fatalf("SAR Create ran %d times for 2 failing checks, want 2 (errors must not be cached)", got)
	}

	// The API server recovers; the very next check must go live and succeed.
	reviewer.set(allowAll)

	_, target, err := sar.ConsumeImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
	if err != nil || target == nil || target.GetName() != "bob" {
		t.Fatalf("post-recovery check: target = %+v, err = %v, want allow", target, err)
	}
	if got := reviewer.calls.Load(); got != 3 {
		t.Errorf("SAR Create ran %d times, want 3", got)
	}
}

// TestCacheDisabled verifies that TTLs of zero disable the cache entirely:
// every check reaches the API server.
func TestCacheDisabled(t *testing.T) {
	reviewer := &fnReviewer{}
	reviewer.set(allowAll)
	sar := New(reviewer, Config{Timeout: DefaultTimeout, AllowCacheTTL: 0, DenyCacheTTL: 0, MaxHeaderValues: DefaultMaxHeaderValues}, slog.New(slog.DiscardHandler))
	if sar.cache != nil {
		t.Fatal("cache is non-nil with both TTLs zero, want fully disabled")
	}

	for i := 0; i < 2; i++ {
		if _, _, err := sar.ConsumeImpersonation(impersonateUserRequest("bob"), cacheTestRequester()); err != nil {
			t.Fatalf("check %d: unexpected error: %v", i, err)
		}
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times with the cache disabled, want 2", got)
	}
}

// TestDecisionCacheBound verifies the cache enforces its size bound by
// evicting the least recently used entry, so attacker-minted keys cannot grow
// memory without limit.
func TestDecisionCacheBound(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	cache := newDecisionCache(time.Minute, time.Minute, 2, clk)

	names := []string{"user-0", "user-1", "user-2"}
	keys := make([]string, 0, len(names))
	for _, n := range names {
		spec := impersonationReviewSpec(userImpersonation(n), cacheTestRequester())
		key, ok := cache.key(&spec)
		if !ok {
			t.Fatalf("key(%s) not cacheable", n)
		}
		keys = append(keys, key)
		cache.put(key, true)
	}

	if _, ok := cache.get(keys[0]); ok {
		t.Error("oldest entry still cached after exceeding the size bound, want LRU eviction")
	}
	for i := 1; i < 3; i++ {
		if allowed, ok := cache.get(keys[i]); !ok || !allowed {
			t.Errorf("entry %d: got (allowed=%t, ok=%t), want cached allow", i, allowed, ok)
		}
	}
}

// TestOversizedSpecNotCached verifies that an absurdly long impersonation
// header value is authorized live but never cached, so clients cannot fill the
// cache with huge keys.
func TestOversizedSpecNotCached(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &fnReviewer{}
	reviewer.set(allowAll)
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	huge := strings.Repeat("a", maxCacheKeySize)

	spec := impersonationReviewSpec(userImpersonation(huge), cacheTestRequester())
	if _, ok := sar.cache.key(&spec); ok {
		t.Fatal("oversized spec reported cacheable, want not cacheable")
	}

	for i := 0; i < 2; i++ {
		_, target, err := sar.ConsumeImpersonation(impersonateUserRequest(huge), cacheTestRequester())
		if err != nil || target == nil || target.GetName() != huge {
			t.Fatalf("check %d: target name mismatch or err = %v, want live allow", i, err)
		}
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times, want 2 (oversized specs must be checked live every time)", got)
	}
}

// gatedReviewer blocks every Create until released, so tests can pile up
// concurrent identical checks behind one in-flight SAR call.
type gatedReviewer struct {
	calls   atomic.Int64
	entered chan struct{}
	release chan struct{}
}

func (r *gatedReviewer) Create(_ context.Context, req *azv1.SubjectAccessReview, _ metav1.CreateOptions) (*azv1.SubjectAccessReview, error) {
	r.calls.Add(1)
	r.entered <- struct{}{}
	<-r.release
	req.Status = azv1.SubjectAccessReviewStatus{Allowed: true}
	return req, nil
}

// winnerCancelReviewer fails the first Create with its caller's context error
// once that context is canceled; later Creates succeed immediately.
type winnerCancelReviewer struct {
	calls   atomic.Int64
	entered chan struct{}
}

func (r *winnerCancelReviewer) Create(ctx context.Context, req *azv1.SubjectAccessReview, _ metav1.CreateOptions) (*azv1.SubjectAccessReview, error) {
	if r.calls.Add(1) == 1 {
		r.entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	req.Status = azv1.SubjectAccessReviewStatus{Allowed: true}
	return req, nil
}
