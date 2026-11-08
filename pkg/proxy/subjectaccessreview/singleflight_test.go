// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
	"testing"
	"time"

	"k8s.io/apiserver/pkg/authentication/user"
)

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

	// Every caller reports when it is about to join the flight, so the gate
	// opens only once all of them are in: no sleep decides the outcome.
	joined := make(chan struct{}, concurrent)
	sar.beforeFlight = func() { joined <- struct{}{} }

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
	for i := 0; i < concurrent; i++ {
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Fatal("not every caller reached the singleflight boundary")
		}
	}
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

// TestSingleflightWinnerCancellationDoesNotPoisonWaiters verifies that when
// the request owning the shared in-flight SAR call is canceled, a concurrent
// request that joined the flight falls back to its own live check instead of
// failing with someone else's context error.
func TestSingleflightWinnerCancellationDoesNotPoisonWaiters(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &winnerCancelReviewer{entered: make(chan struct{}, 1)}
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	winnerCtx, cancelWinner := context.WithCancel(testRequestContext())
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
