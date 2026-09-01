// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
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
func newCachedSAR(r clientazv1.SubjectAccessReviewInterface, allowTTL, denyTTL time.Duration, clk utilcache.Clock) *SubjectAccessReview {
	return &SubjectAccessReview{
		reviewer:   r,
		sarTimeout: DefaultTimeout,
		cache:      newDecisionCache(allowTTL, denyTTL, decisionCacheSize, clk),
	}
}

// impersonateUserRequest returns a fresh request carrying a single
// Impersonate-User header. A new request is needed per check because a
// successful check strips the impersonation headers from the request.
func impersonateUserRequest(name string) *http.Request {
	h := http.Header{}
	h.Set("Impersonate-User", name)
	return (&http.Request{Header: h}).WithContext(context.Background())
}

func cacheTestRequester() *user.DefaultInfo {
	return &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}
}

// TestDecisionCacheKeyCollisionResistance pins that identities and targets
// whose naive string concatenation would coincide produce distinct cache keys.
// A collision here would be a privilege escalation: one principal inheriting
// another's cached allow decision.
func TestDecisionCacheKeyCollisionResistance(t *testing.T) {
	type input struct {
		resource  string
		name      string
		requester user.Info
	}

	// Every entry must produce a key distinct from every other entry. Several
	// pairs are crafted so that concatenating their identity fields yields the
	// same string.
	tests := map[string]input{
		"alice impersonates bob": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"requester/name boundary shifted": {
			// Naive requester+resource+name concatenation collides with the
			// case above: "aliceusers"+"users"+"bob" vs "alice"+"users"+"usersbob".
			resource: "users", name: "usersbob",
			requester: &user.DefaultInfo{Name: "aliceusers"},
		},
		"boundary-shift counterpart": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "aliceusers"},
		},
		"two groups": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Groups: []string{"g1", "g2"}},
		},
		"one group with separator in name": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Groups: []string{"g1,g2"}},
		},
		"group boundary shifted": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Groups: []string{"g", "1g2"}},
		},
		"extra with two values": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"k": {"ab", "c"}}},
		},
		"extra value boundary shifted": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"k": {"a", "bc"}}},
		},
		"extra key/value boundary shifted": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"ka": {"b", "c"}}},
		},
		"group vs extra holding same strings": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"g1": {"g2"}}},
		},
		"same target as group kind": {
			resource: "groups", name: "bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"same target as uid kind": {
			resource: "uids", name: "bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"same target as extra kind": {
			resource: "userextras/team", name: "bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"subresource/name boundary shifted": {
			resource: "userextras/teambob", name: "",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"colon-joined concatenation, colon in requester": {
			// Colon-delimited requester:resource:name concatenation renders
			// this and the case below as "alice:users:bob".
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice:users"},
		},
		"colon-joined concatenation, colon in target": {
			resource: "users", name: "users:bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"space-joined concatenation, space in requester": {
			// Space-delimited concatenation renders this and the case below
			// as "alice users bob".
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice users"},
		},
		"space-joined concatenation, space in target": {
			resource: "users", name: "users bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"unicode requester": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "ålice"},
		},
		"unicode target, precomposed form": {
			// U+00F6 LATIN SMALL LETTER O WITH DIAERESIS.
			resource: "users", name: "böb",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"unicode target, decomposed form": {
			// "o" followed by U+0308 COMBINING DIAERESIS: canonically equivalent
			// to the precomposed case yet a distinct byte sequence, so it must
			// remain a distinct authorization question and key.
			resource: "users", name: "bo\u0308b",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"empty requester name": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: ""},
		},
		"empty group name": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Groups: []string{""}},
		},
		"empty extra value": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"k": {""}}},
		},
		"extra key with no values": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"k": {}}},
		},
		"requester uid": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", UID: "uid-1"},
		},
		"same identity differing only in uid": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", UID: "uid-2"},
		},
	}

	cache := newDecisionCache(time.Minute, time.Minute, decisionCacheSize, &fakeClock{})

	keys := map[string]string{}
	for testName, in := range tests {
		spec := impersonationReviewSpec(in.resource, in.name, in.requester)
		key, ok := cache.key(&spec)
		if !ok {
			t.Fatalf("%s: key() not cacheable, want cacheable", testName)
		}
		if prev, exists := keys[key]; exists {
			t.Errorf("cache key collision between %q and %q: %s", prev, testName, key)
		}
		keys[key] = testName
	}
}

// TestCacheAllowHitAndExpiry verifies an allowed decision is served from the
// cache for its TTL and re-checked live once the TTL elapses.
func TestCacheAllowHitAndExpiry(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &fnReviewer{}
	reviewer.set(allowAll)
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	for i := 0; i < 3; i++ {
		target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
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

	if _, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester()); err != nil {
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

	wantDenial := ImpersonationAuthError{Requester: "mmosley", Kind: "user", Target: "'bob'"}

	target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
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

	target, err = sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
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

	target, err = sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
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

	if _, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester()); !errors.Is(err, ErrImpersonationNotAllowed) {
		t.Fatalf("first check: error = %v, want denial", err)
	}

	reviewer.set(allowAll)

	target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
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
		_, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
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

	target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
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
	sar, err := New(reviewer, DefaultTimeout, 0, 0)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if sar.cache != nil {
		t.Fatal("cache is non-nil with both TTLs zero, want fully disabled")
	}

	for i := 0; i < 2; i++ {
		if _, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester()); err != nil {
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
		spec := impersonationReviewSpec("users", n, cacheTestRequester())
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

	spec := impersonationReviewSpec("users", huge, cacheTestRequester())
	if _, ok := sar.cache.key(&spec); ok {
		t.Fatal("oversized spec reported cacheable, want not cacheable")
	}

	for i := 0; i < 2; i++ {
		target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest(huge), cacheTestRequester())
		if err != nil || target == nil || target.GetName() != huge {
			t.Fatalf("check %d: target name mismatch or err = %v, want live allow", i, err)
		}
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times, want 2 (oversized specs must be checked live every time)", got)
	}
}

// TestRequesterExtrasPartitionCache verifies that two requesters differing
// only in their Extra fields never share cache entries — extras influence the
// SAR outcome, so omitting them from the key would leak decisions across
// principals.
func TestRequesterExtrasPartitionCache(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &fnReviewer{}
	reviewer.set(allowAll)
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	requesterA := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}, Extra: map[string][]string{"project": {"a"}}}
	requesterB := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}, Extra: map[string][]string{"project": {"b"}}}

	if _, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), requesterA); err != nil {
		t.Fatalf("requester A: unexpected error: %v", err)
	}
	if _, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), requesterA); err != nil {
		t.Fatalf("requester A repeat: unexpected error: %v", err)
	}
	if got := reviewer.calls.Load(); got != 1 {
		t.Fatalf("SAR Create ran %d times for requester A, want 1 (cache hit)", got)
	}

	if _, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), requesterB); err != nil {
		t.Fatalf("requester B: unexpected error: %v", err)
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times, want 2 (requester B must not inherit A's cached decision)", got)
	}
}

// TestCachedAllowNotLeakedAcrossNaiveCollision is the behavioral counterpart
// of the key-collision test: a principal whose identity fields concatenate to
// the same string as an authorized principal's must still be checked live and
// denied.
func TestCachedAllowNotLeakedAcrossNaiveCollision(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &fnReviewer{}
	// Only "aliceusers" holds the impersonation grant.
	reviewer.set(func(req *azv1.SubjectAccessReview) (*azv1.SubjectAccessReview, error) {
		req.Status = azv1.SubjectAccessReviewStatus{Allowed: req.Spec.User == "aliceusers"}
		return req, nil
	})
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	// Naive requester+resource+name concatenation renders both checks as
	// "aliceusers" + "users" + "bob" == "alice" + "users" + "usersbob".
	privileged := &user.DefaultInfo{Name: "aliceusers"}
	target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), privileged)
	if err != nil || target == nil {
		t.Fatalf("privileged requester: target = %+v, err = %v, want allow", target, err)
	}

	attacker := &user.DefaultInfo{Name: "alice"}
	target, err = sar.CheckAuthorizedForImpersonation(impersonateUserRequest("usersbob"), attacker)
	if target != nil || !errors.Is(err, ErrImpersonationNotAllowed) {
		t.Fatalf("colliding requester: target = %+v, err = %v, want denial (must not inherit cached allow)", target, err)
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times, want 2 (colliding identity must be checked live)", got)
	}
}

// TestCachedAllowNotInheritedAcrossUID verifies that two principals identical
// in name, groups, and extras but differing in UID never share a cached
// decision: the requester's UID is part of the submitted SAR spec and
// therefore of the cache key, so the second principal must be checked live
// and denied rather than inheriting the first principal's cached allow.
func TestCachedAllowNotInheritedAcrossUID(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &fnReviewer{}
	// Only the principal with UID "uid-allowed" holds the impersonation grant.
	reviewer.set(func(req *azv1.SubjectAccessReview) (*azv1.SubjectAccessReview, error) {
		req.Status = azv1.SubjectAccessReviewStatus{Allowed: req.Spec.UID == "uid-allowed"}
		return req, nil
	})
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	privileged := &user.DefaultInfo{Name: "mmosley", UID: "uid-allowed", Groups: []string{"group1"}}
	target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), privileged)
	if err != nil || target == nil || target.GetName() != "bob" {
		t.Fatalf("privileged principal: target = %+v, err = %v, want allow", target, err)
	}

	// Same name, groups, and extras — only the UID differs.
	imposter := &user.DefaultInfo{Name: "mmosley", UID: "uid-other", Groups: []string{"group1"}}
	target, err = sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), imposter)
	if target != nil || !errors.Is(err, ErrImpersonationNotAllowed) {
		t.Fatalf("differing-UID principal: target = %+v, err = %v, want denial (must not inherit cached allow)", target, err)
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times, want 2 (differing-UID principal must be checked live)", got)
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

// TestSingleflightDedup verifies that a burst of concurrent identical checks
// collapses into a single live SAR call whose decision every caller receives.
func TestSingleflightDedup(t *testing.T) {
	const concurrent = 5

	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &gatedReviewer{
		entered: make(chan struct{}, concurrent),
		release: make(chan struct{}),
	}
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	results := make(chan error, concurrent)
	check := func() {
		target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
		if err == nil && (target == nil || target.GetName() != "bob") {
			err = errors.New("allowed check returned wrong target")
		}
		results <- err
	}

	go check()
	select {
	case <-reviewer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first SAR Create was never entered")
	}

	// With the first call blocked in flight, later identical checks must join
	// it rather than issue their own.
	for i := 1; i < concurrent; i++ {
		go check()
	}
	time.Sleep(300 * time.Millisecond)
	close(reviewer.release)

	for i := 0; i < concurrent; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("concurrent check error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent check never returned")
		}
	}

	if got := reviewer.calls.Load(); got != 1 {
		t.Errorf("SAR Create ran %d times for %d concurrent identical checks, want 1", got, concurrent)
	}
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

// TestSingleflightWinnerCancellationDoesNotPoisonWaiters verifies that when
// the request owning the shared in-flight SAR call is canceled, a concurrent
// request that joined the flight falls back to its own live check instead of
// failing with someone else's context error.
func TestSingleflightWinnerCancellationDoesNotPoisonWaiters(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &winnerCancelReviewer{entered: make(chan struct{}, 1)}
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	winnerCtx, cancelWinner := context.WithCancel(context.Background())
	defer cancelWinner()

	type outcome struct {
		target user.Info
		err    error
	}

	winnerDone := make(chan outcome, 1)
	go func() {
		req := impersonateUserRequest("bob").WithContext(winnerCtx)
		target, err := sar.CheckAuthorizedForImpersonation(req, cacheTestRequester())
		winnerDone <- outcome{target, err}
	}()

	select {
	case <-reviewer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first SAR Create was never entered")
	}

	waiterDone := make(chan outcome, 1)
	go func() {
		target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
		waiterDone <- outcome{target, err}
	}()

	// Give the waiter time to join the in-flight call, then cancel its owner.
	time.Sleep(300 * time.Millisecond)
	cancelWinner()

	select {
	case res := <-winnerDone:
		if !errors.Is(res.err, context.Canceled) {
			t.Errorf("winner error = %v, want errors.Is(context.Canceled)", res.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("winner never returned after cancellation")
	}

	select {
	case res := <-waiterDone:
		if res.err != nil {
			t.Errorf("waiter error = %v, want success via direct fallback check", res.err)
		} else if res.target == nil || res.target.GetName() != "bob" {
			t.Errorf("waiter target = %+v, want user bob", res.target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter never returned")
	}
}
