// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"k8s.io/apiserver/pkg/authentication/user"
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
				target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
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
			target, err := sar.CheckAuthorizedForImpersonation(req, cacheTestRequester())
			winnerDone <- outcome{target, err}
		}()
		synctest.Wait()

		waiterDone := make(chan outcome, 1)
		go func() {
			target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), cacheTestRequester())
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
