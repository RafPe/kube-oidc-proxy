// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

// The coalescing tests run in a synctest bubble. synctest.Wait returns only
// once every goroutine in the bubble is durably blocked, so when it returns
// the first caller is inside the review and every other caller is waiting on
// the shared flight. A signal sent before a caller joins the flight cannot
// promise that: the caller can be descheduled between the signal and the
// join, miss a flight that has just finished, and start a second one.

// TestSingleflightDedup verifies that a burst of concurrent identical checks
// collapses into a single live SAR call whose decision every caller receives.
func TestSingleflightDedup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const concurrent = 5

		clk := &fakeClock{now: time.Unix(1000, 0)}
		reviewer := &gatedReviewer{
			entered: make(chan struct{}, concurrent),
			release: make(chan struct{}),
		}
		sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

		results := make(chan error, concurrent)
		for i := 0; i < concurrent; i++ {
			go func() {
				target, err := sar.ResolveImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
				if err == nil && (target == nil || target.GetName() != "bob") {
					err = errors.New("allowed check returned wrong target")
				}
				results <- err
			}()
		}

		// One caller is blocked in Create, the rest on its flight.
		synctest.Wait()
		if got := reviewer.calls.Load(); got != 1 {
			t.Fatalf("SAR Create ran %d times while the burst was in flight, want 1", got)
		}
		close(reviewer.release)

		for i := 0; i < concurrent; i++ {
			if err := <-results; err != nil {
				t.Errorf("concurrent check error: %v", err)
			}
		}
		if got := reviewer.calls.Load(); got != 1 {
			t.Errorf("SAR Create ran %d times for %d concurrent identical checks, want 1", got, concurrent)
		}
	})
}

// TestSingleflightWinnerCancellationDoesNotPoisonWaiters verifies that when
// the request owning the shared in-flight SAR call is canceled, a concurrent
// request that joined the flight falls back to its own live check instead of
// failing with someone else's context error.
func TestSingleflightWinnerCancellationDoesNotPoisonWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clk := &fakeClock{now: time.Unix(1000, 0)}
		reviewer := &winnerCancelReviewer{entered: make(chan struct{}, 1)}
		sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

		type outcome struct {
			target user.Info
			err    error
		}

		winnerCtx, cancelWinner := context.WithCancel(testRequestContext())
		defer cancelWinner()

		winnerDone := make(chan outcome, 1)
		go func() {
			req := impersonateUserRequest("bob").WithContext(winnerCtx)
			target, err := sar.ResolveImpersonation(req, cacheTestRequester())
			winnerDone <- outcome{target, err}
		}()
		synctest.Wait()

		waiterDone := make(chan outcome, 1)
		go func() {
			target, err := sar.ResolveImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
			waiterDone <- outcome{target, err}
		}()

		// The winner is blocked in Create and the waiter on its flight.
		synctest.Wait()
		if got := reviewer.calls.Load(); got != 1 {
			t.Fatalf("SAR Create ran %d times before the cancel, want 1 (the waiter must have joined the flight)", got)
		}
		cancelWinner()

		if res := <-winnerDone; !errors.Is(res.err, context.Canceled) {
			t.Errorf("winner error = %v, want errors.Is(context.Canceled)", res.err)
		}
		res := <-waiterDone
		if res.err != nil {
			t.Errorf("waiter error = %v, want success via direct fallback check", res.err)
		} else if res.target == nil || res.target.GetName() != "bob" {
			t.Errorf("waiter target = %+v, want user bob", res.target)
		}
	})
}

// TestSingleflightLeaderContextErrorIsItsOwn verifies that the caller leading
// a flight reports a context-shaped failure of its own review as is, while its
// own request is still alive, instead of mistaking it for another request's
// cancellation: it sends no second review and emits exactly one failure
// record. The joiner, whose flight failed for a reason not its own, still
// retries with a check of its own.
func TestSingleflightLeaderContextErrorIsItsOwn(t *testing.T) {
	root, cap := logtest.New(t, 2)
	defer logtest.AssertRegistered(t, cap)

	synctest.Test(t, func(t *testing.T) {
		reviewer := &deadlineOnceReviewer{release: make(chan struct{})}
		s := newLoggingSAR(t, root, reviewer, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)

		check := func(requestID string) <-chan error {
			done := make(chan error, 1)
			go func() {
				ctx := logging.WithRequestID(context.Background(), requestID)
				_, err := s.cachedCheck(directCall(ctx, loggingTestRequester()), userImpersonation("bob"))
				done <- err
			}()
			return done
		}

		leader := check("leader")
		synctest.Wait()
		joiner := check("joiner")
		synctest.Wait()
		close(reviewer.release)

		if err := <-leader; !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("leader error = %v, want its own review's errors.Is(context.DeadlineExceeded)", err)
		}
		if err := <-joiner; err != nil {
			t.Errorf("joiner error = %v, want success via its own retry", err)
		}
		if got := reviewer.calls.Load(); got != 2 {
			t.Errorf("SAR Create ran %d times, want 2 (the shared review and the joiner's retry only)", got)
		}
	})

	failed := cap.ByEvent(logging.EventAuthzSARFailed)
	if len(failed) != 1 || failed[0].String("request_id") != "leader" {
		t.Fatalf("want exactly one failure record, the leader's, got %v", failed)
	}
}

// deadlineOnceReviewer fails its first Create, once released, with a
// deadline error of the review client's own (the caller's context is still
// alive); later Creates allow immediately.
type deadlineOnceReviewer struct {
	calls   atomic.Int64
	release chan struct{}
}

func (r *deadlineOnceReviewer) Create(_ context.Context, req *v1.SubjectAccessReview, _ metav1.CreateOptions) (*v1.SubjectAccessReview, error) {
	if r.calls.Add(1) == 1 {
		<-r.release
		return nil, context.DeadlineExceeded
	}
	req.Status = v1.SubjectAccessReviewStatus{Allowed: true}
	return req, nil
}
