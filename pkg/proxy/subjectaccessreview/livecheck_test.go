// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	v1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

// newLoggingSAR builds a reviewer that logs through root as the sar component,
// so the records a check emits are observable with the given cache TTLs.
func newLoggingSAR(t *testing.T, root *slog.Logger, r clientazv1.SubjectAccessReviewInterface, sarTimeout, allowTTL, denyTTL time.Duration) *SubjectAccessReview {
	t.Helper()

	s, err := New(r, Config{Timeout: sarTimeout, AllowCacheTTL: allowTTL, DenyCacheTTL: denyTTL, MaxHeaderValues: DefaultMaxHeaderValues}, logging.ForComponent(root, logging.ComponentSAR))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return s
}

// newSARWithFakeReviewer builds a logging reviewer that answers every review
// with decide. Both cache TTLs are non-zero so the decision cache is live and
// hit/miss lookups are observable.
func newSARWithFakeReviewer(t *testing.T, root *slog.Logger, decide func(*v1.SubjectAccessReview) (*v1.SubjectAccessReview, error)) *SubjectAccessReview {
	t.Helper()

	return newLoggingSAR(t, root, &fnReviewer{fn: decide}, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)
}

// loggingTestRequester is the authenticated identity the logging tests ask
// their authorization questions on behalf of.
func loggingTestRequester() *user.DefaultInfo {
	return &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}
}

// TestCacheHitAndLiveCheckEvents pins the records one authorization check
// emits: a cache lookup every time, a completed live review only when the
// cache did not answer, and never any cache key material.
func TestCacheHitAndLiveCheckEvents(t *testing.T) {
	root, cap := logtest.New(t, 2)
	defer logtest.AssertRegistered(t, cap)
	s := newSARWithFakeReviewer(t, root, allowAll)
	requester := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}
	ctx := logging.WithRequestID(context.Background(), "r1")

	if _, err := s.cachedCheck(directCall(ctx, requester), userImpersonation("bob")); err != nil {
		t.Fatal(err)
	}
	miss := cap.ByEvent(logging.EventCacheSARLookup)
	if len(miss) != 1 || miss[0].String("cache_result") != "miss" {
		t.Fatalf("%v", miss)
	}
	live := cap.Only(t, logging.EventAuthzSARCompleted)
	if live.String("decision") != "allow" || live.String("request_id") != "r1" || live["request_coalesced"] != false {
		t.Fatalf("%v", live)
	}
	if _, ok := live.Int("duration_ms"); !ok {
		t.Fatal("duration_ms missing")
	}

	if _, err := s.cachedCheck(directCall(ctx, requester), userImpersonation("bob")); err != nil {
		t.Fatal(err)
	}
	hits := cap.ByEvent(logging.EventCacheSARLookup)
	if len(hits) != 2 || hits[1].String("cache_result") != "hit" || hits[1].String("decision") != "allow" {
		t.Fatalf("%v", hits)
	}
	if strings.Contains(cap.Raw(), `"spec"`) || strings.Contains(cap.Raw(), "SubjectAccessReviewSpec") {
		t.Fatal("cache key material logged")
	}
}

// TestCacheBypassEvents covers the two ways a decision is never cacheable: the
// cache is switched off entirely, and the serialized spec is over the key-size
// cap. Both report cache_result=bypass and still complete a live review.
func TestCacheBypassEvents(t *testing.T) {
	tests := map[string]struct {
		allowTTL, denyTTL time.Duration
		name              string
	}{
		"a disabled cache bypasses every lookup": {
			allowTTL: 0,
			denyTTL:  0,
			name:     "bob",
		},
		"a spec over the key-size cap bypasses the cache": {
			allowTTL: DefaultAllowCacheTTL,
			denyTTL:  DefaultDenyCacheTTL,
			name:     strings.Repeat("a", maxCacheKeySize+1),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root, cap := logtest.New(t, 2)
			defer logtest.AssertRegistered(t, cap)
			s := newLoggingSAR(t, root, &fnReviewer{fn: allowAll}, DefaultTimeout, tc.allowTTL, tc.denyTTL)
			ctx := logging.WithRequestID(context.Background(), "r1")

			for i := range 2 {
				if _, err := s.cachedCheck(directCall(ctx, loggingTestRequester()), userImpersonation(tc.name)); err != nil {
					t.Fatalf("check %d: %v", i, err)
				}
			}

			lookups := cap.ByEvent(logging.EventCacheSARLookup)
			if len(lookups) != 2 {
				t.Fatalf("want 2 cache lookups, got %d: %v", len(lookups), lookups)
			}
			for i, rec := range lookups {
				if rec.String("cache_result") != "bypass" {
					t.Errorf("lookup %d: cache_result = %q, want bypass", i, rec.String("cache_result"))
				}
				if rec.String("decision") != "" {
					t.Errorf("lookup %d: bypass must not carry a decision, got %q", i, rec.String("decision"))
				}
			}

			// Nothing was cached, so both checks reached the API server.
			live := cap.ByEvent(logging.EventAuthzSARCompleted)
			if len(live) != 2 {
				t.Fatalf("want 2 completed reviews, got %d: %v", len(live), live)
			}
		})
	}
}

// TestCachedDenyDecisionEvents pins that a denial is cached and served like an
// allow: the second lookup is a hit carrying decision=deny, and no second
// review is run.
func TestCachedDenyDecisionEvents(t *testing.T) {
	root, cap := logtest.New(t, 2)
	defer logtest.AssertRegistered(t, cap)
	reviewer := &fnReviewer{fn: denyAll}
	s := newLoggingSAR(t, root, reviewer, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)
	ctx := logging.WithRequestID(context.Background(), "r1")

	for i := range 2 {
		allowed, err := s.cachedCheck(directCall(ctx, loggingTestRequester()), groupImpersonation("group3"))
		if err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
		if allowed {
			t.Fatalf("check %d: want the review denied", i)
		}
	}

	lookups := cap.ByEvent(logging.EventCacheSARLookup)
	if len(lookups) != 2 || lookups[0].String("cache_result") != "miss" {
		t.Fatalf("want a miss then a hit, got %v", lookups)
	}
	if lookups[1].String("cache_result") != "hit" || lookups[1].String("decision") != "deny" {
		t.Fatalf("want hit with decision=deny, got %v", lookups[1])
	}

	live := cap.Only(t, logging.EventAuthzSARCompleted)
	if live.String("decision") != "deny" || live.String("target_kind") != "group" {
		t.Fatalf("%v", live)
	}
	if got := reviewer.calls.Load(); got != 1 {
		t.Errorf("SAR Create ran %d times, want 1 (the deny must be cached)", got)
	}
}

// TestLiveCheckFailureEvents pins how a failed review is classified: an API
// server that answers with an error is an ERROR dependency failure, while the
// requester abandoning its own request is a DEBUG per-request condition a
// client must not be able to drive to ERROR at will.
func TestLiveCheckFailureEvents(t *testing.T) {
	t.Run("an apiserver error is an ERROR dependency failure", func(t *testing.T) {
		root, cap := logtest.New(t, 2)
		defer logtest.AssertRegistered(t, cap)
		s := newLoggingSAR(t, root, &fnReviewer{fn: failWith(errReview)}, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)
		ctx := logging.WithRequestID(context.Background(), "r1")

		if _, err := s.cachedCheck(directCall(ctx, loggingTestRequester()), userImpersonation("bob")); !errors.Is(err, ErrCreateSubjectAccessReview) {
			t.Fatalf("error = %v, want errors.Is(ErrCreateSubjectAccessReview)", err)
		}

		rec := cap.Only(t, logging.EventAuthzSARFailed)
		if rec.String("level") != "ERROR" {
			t.Errorf("level = %q, want ERROR", rec.String("level"))
		}
		if rec.String("reason") != "authorization_dependency_error" {
			t.Errorf("reason = %q, want authorization_dependency_error", rec.String("reason"))
		}
		if !strings.Contains(rec.String("error_message"), errReview.Error()) {
			t.Errorf("error_message = %q, want it to carry the underlying error", rec.String("error_message"))
		}
		if rec.String("request_id") != "r1" {
			t.Errorf("request_id = %q, want r1", rec.String("request_id"))
		}
		// A failure is not an authorization answer.
		if got := cap.ByEvent(logging.EventAuthzSARCompleted); len(got) != 0 {
			t.Errorf("a failed review must not emit a completion record, got %v", got)
		}
	})

	t.Run("caller cancellation is a DEBUG client condition", func(t *testing.T) {
		root, cap := logtest.New(t, 2)
		defer logtest.AssertRegistered(t, cap)
		reviewer := &blockingReviewer{entered: make(chan struct{}, 1)}
		s := newLoggingSAR(t, root, reviewer, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)

		ctx, cancel := context.WithCancel(logging.WithRequestID(context.Background(), "r1"))
		defer cancel()

		done := make(chan error, 1)
		go func() {
			_, err := s.cachedCheck(directCall(ctx, loggingTestRequester()), userImpersonation("bob"))
			done <- err
		}()

		select {
		case <-reviewer.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("SAR Create was never entered")
		}
		cancel()

		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want errors.Is(context.Canceled)", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("the check never returned after cancellation")
		}

		rec := cap.Only(t, logging.EventAuthzSARFailed)
		if rec.String("level") != "DEBUG" {
			t.Errorf("level = %q, want DEBUG: a client disconnect must not raise an ERROR", rec.String("level"))
		}
		if rec.String("reason") != "client_canceled" {
			t.Errorf("reason = %q, want client_canceled", rec.String("reason"))
		}
		if rec.String("error_message") == "" {
			t.Error("error_message must still carry the bounded cause")
		}
		if rec.String("request_id") != "r1" {
			t.Errorf("request_id = %q, want r1", rec.String("request_id"))
		}
	})

	t.Run("the proxy's own authorization budget expiring is an ERROR dependency failure", func(t *testing.T) {
		root, cap := logtest.New(t, 2)
		defer logtest.AssertRegistered(t, cap)
		reviewer := &blockingReviewer{entered: make(chan struct{}, 1)}
		s := newLoggingSAR(t, root, reviewer, 50*time.Millisecond, DefaultAllowCacheTTL, DefaultDenyCacheTTL)

		h := http.Header{}
		h.Set("Impersonate-User", "bob")
		// The requester never goes away: the only deadline that can expire is
		// the proxy's own SAR budget, which means the API server did not answer
		// in time. That is a dependency failure, not a client condition.
		req := (&http.Request{Header: h}).WithContext(logging.WithRequestID(context.Background(), "r1"))

		done := make(chan error, 1)
		go func() {
			_, err := s.ResolveImpersonation(req, loggingTestRequester())
			done <- err
		}()

		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error = %v, want errors.Is(context.DeadlineExceeded)", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("the check never returned after the authorization budget expired")
		}

		rec := cap.Only(t, logging.EventAuthzSARFailed)
		if rec.String("level") != "ERROR" {
			t.Errorf("level = %q, want ERROR: a slow API server is a dependency failure", rec.String("level"))
		}
		if rec.String("reason") != "authorization_dependency_error" {
			t.Errorf("reason = %q, want authorization_dependency_error", rec.String("reason"))
		}
		if !strings.Contains(rec.String("error_message"), "timed out") {
			t.Errorf("error_message = %q, want it to say the subject access review timed out", rec.String("error_message"))
		}
		if rec.String("request_id") != "r1" {
			t.Errorf("request_id = %q, want r1", rec.String("request_id"))
		}
	})

	t.Run("a client disconnect on the request path stays a DEBUG client condition", func(t *testing.T) {
		root, cap := logtest.New(t, 2)
		defer logtest.AssertRegistered(t, cap)
		reviewer := &blockingReviewer{entered: make(chan struct{}, 1)}
		// A generous authorization budget, so the only deadline that can fire is
		// the requester's own. This is the production path, where the derived
		// context carries the parent to classify against; the direct-call subtest
		// above exercises the fallback for a check with no recorded parent.
		s := newLoggingSAR(t, root, reviewer, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)

		reqCtx, cancel := context.WithCancel(logging.WithRequestID(context.Background(), "r1"))
		defer cancel()

		h := http.Header{}
		h.Set("Impersonate-User", "bob")
		req := (&http.Request{Header: h}).WithContext(reqCtx)

		done := make(chan error, 1)
		go func() {
			_, err := s.ResolveImpersonation(req, loggingTestRequester())
			done <- err
		}()

		select {
		case <-reviewer.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("SAR Create was never entered")
		}
		cancel()

		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want errors.Is(context.Canceled)", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("the check never returned after the client disconnected")
		}

		rec := cap.Only(t, logging.EventAuthzSARFailed)
		if rec.String("level") != "DEBUG" {
			t.Errorf("level = %q, want DEBUG: a client disconnect must not raise an ERROR", rec.String("level"))
		}
		if rec.String("reason") != "client_canceled" {
			t.Errorf("reason = %q, want client_canceled", rec.String("reason"))
		}
		if strings.Contains(rec.String("error_message"), "timed out") {
			t.Errorf("error_message = %q, must not blame the API server for a client disconnect", rec.String("error_message"))
		}
	})
}

// TestCoalescedLiveCheckEvent pins request_coalesced: two callers asking the
// identical authorization question share one SubjectAccessReview, and each
// reports its own completion record. Only the caller that joined the other's
// flight is coalesced; the leader ran the review itself, even though
// singleflight marks its result Shared too once anyone joined. It runs in a
// synctest bubble for the reason given in singleflight_test.go.
func TestCoalescedLiveCheckEvent(t *testing.T) {
	root, cap := logtest.New(t, 2)
	defer logtest.AssertRegistered(t, cap)

	synctest.Test(t, func(t *testing.T) {
		reviewer := &gateReviewer{entered: make(chan struct{}, 1), release: make(chan struct{})}
		s := newLoggingSAR(t, root, reviewer, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)

		var wg sync.WaitGroup
		errs := make(map[string]error, 2)
		var mu sync.Mutex
		check := func(requestID string) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx := logging.WithRequestID(context.Background(), requestID)
				_, err := s.cachedCheck(directCall(ctx, loggingTestRequester()), userImpersonation("bob"))
				mu.Lock()
				errs[requestID] = err
				mu.Unlock()
			}()
		}

		// The leader is blocked in Create before the joiner starts, so which
		// caller leads is fixed rather than left to the scheduler.
		check("leader")
		synctest.Wait()
		check("joiner")
		synctest.Wait()
		close(reviewer.release)
		wg.Wait()

		for id, err := range errs {
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
		}
		if got := reviewer.calls.Load(); got != 1 {
			t.Fatalf("SAR Create ran %d times, want 1 (the two callers must share one review)", got)
		}
	})

	live := cap.ByEvent(logging.EventAuthzSARCompleted)
	if len(live) != 2 {
		t.Fatalf("want one completion record per caller, got %d: %v", len(live), live)
	}
	want := map[string]bool{"leader": false, "joiner": true}
	for _, rec := range live {
		id := rec.String("request_id")
		coalesced, ok := want[id]
		if !ok {
			t.Fatalf("unexpected completion record %v", rec)
		}
		delete(want, id)
		if rec["request_coalesced"] != coalesced {
			t.Errorf("%s: request_coalesced = %v, want %t", id, rec["request_coalesced"], coalesced)
		}
		if rec.String("decision") != "allow" || rec.String("target_kind") != "user" {
			t.Errorf("%s: %v", id, rec)
		}
	}
}

// TestImpersonationResolvedEvent pins the record closing a whole allowed
// impersonation sequence: the user target it resolved to, and nothing else.
func TestImpersonationResolvedEvent(t *testing.T) {
	root, cap := logtest.New(t, 2)
	defer logtest.AssertRegistered(t, cap)
	s := newSARWithFakeReviewer(t, root, allowAll)

	h := http.Header{}
	h.Set("Impersonate-User", "bob")
	req := (&http.Request{Header: h}).WithContext(logging.WithRequestID(context.Background(), "r1"))

	target, err := s.ResolveImpersonation(req, loggingTestRequester())
	if err != nil {
		t.Fatalf("ResolveImpersonation() error = %v", err)
	}
	if target == nil || target.GetName() != "bob" {
		t.Fatalf("target = %v, want the impersonated user bob", target)
	}

	rec := cap.Only(t, logging.EventAuthzImpersonationResolved)
	if rec.String("target_kind") != "user" {
		t.Errorf("target_kind = %q, want user", rec.String("target_kind"))
	}
	if rec.String("target_name") != "bob" {
		t.Errorf("target_name = %q, want bob", rec.String("target_name"))
	}
	if rec.String("request_id") != "r1" {
		t.Errorf("request_id = %q, want r1", rec.String("request_id"))
	}

	live := cap.Only(t, logging.EventAuthzSARCompleted)
	if live.String("target_kind") != "user" {
		t.Errorf("completed target_kind = %q, want user", live.String("target_kind"))
	}
}

// directCall is the reviewCall for a check driven directly by a test: the
// review runs on the request's own context, so the requester's deadline and
// the review's are the same one.
func directCall(ctx context.Context, requester user.Info) reviewCall {
	return reviewCall{ctx: ctx, requestCtx: ctx, requester: requester}
}
