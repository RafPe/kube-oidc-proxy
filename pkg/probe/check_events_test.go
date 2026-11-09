// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

// concurrentAuthenticator records the maximum number of AuthenticateToken calls in
// flight simultaneously. It is used to prove the health-check lock is not held
// across the authenticator call (#53).
type concurrentAuthenticator struct {
	mu      sync.Mutex
	current int
	max     int

	entered chan struct{}
	release chan struct{}
}

func (c *concurrentAuthenticator) AuthenticateToken(_ context.Context, _ string) (*authenticator.Response, bool, error) {
	c.mu.Lock()
	c.current++
	if c.current > c.max {
		c.max = c.current
	}
	c.mu.Unlock()

	c.entered <- struct{}{}
	<-c.release

	c.mu.Lock()
	c.current--
	c.mu.Unlock()

	// Keep the issuer pending so it is probed on every Check.
	return nil, false, errors.New("oidc: authenticator not initialized")
}

func (c *concurrentAuthenticator) maxConcurrent() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.max
}

// TestCheckDoesNotHoldLockDuringAuth verifies the authenticator call runs
// lock-free: two concurrent Check calls must be able to sit inside
// AuthenticateToken simultaneously. If h.mu were held across the call, the
// second Check would block at entry and the two would serialize (max=1),
// causing the barrier read below to time out.
func TestCheckDoesNotHoldLockDuringAuth(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	authn := &concurrentAuthenticator{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	h := newTestHealthCheckWithAuthenticator(true, authn, issuerA)
	// Check returns before reaching the authenticator unless it is serving.
	h.setServing()

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.check()
		}()
	}

	// Both Check calls must reach the authenticator concurrently.
	for i := 0; i < 2; i++ {
		select {
		case <-authn.entered:
		case <-time.After(2 * time.Second):
			close(authn.release)
			t.Fatal("only one Check reached the authenticator: lock held across auth call")
		}
	}

	close(authn.release)
	wg.Wait()

	if got := authn.maxConcurrent(); got < 2 {
		t.Fatalf("expected >=2 concurrent authenticator calls, got %d", got)
	}
}

// TestIssuerPendingEmittedOnStateChangeWithReason pins the pending record to
// state changes: an unchanged pending set must not restate itself on every
// kubelet probe, which would otherwise flood the log for the whole lifetime of
// an unreachable issuer. The record carries the classification the probe
// already computes.
func TestIssuerPendingEmittedOnStateChangeWithReason(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)
	hc := newTestHealthCheckWithLogger(t, root, true, map[string]bool{"https://a": true},
		IssuerReadiness{IssuerURL: "https://a", FakeJWT: "jwt-a"})
	hc.setServing()
	_ = hc.check()
	_ = hc.check()
	recs := cap.ByEvent(logging.EventOIDCIssuerPending)
	if len(recs) != 1 {
		t.Fatalf("pending emitted %d times, want 1", len(recs))
	}
	if recs[0].String("pending_reason") != "not_initialized" || recs[0].String("level") != "WARN" {
		t.Fatalf("%v", recs[0])
	}
}

// TestReadyTransitionIsInfo pins the ready latch to a single INFO record
// naming the readiness mode, inverting the old policy where the transition was
// V(4) while the pending line repeated on every scrape.
func TestReadyTransitionIsInfo(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)
	hc := newTestHealthCheckWithLogger(t, root, false, nil, IssuerReadiness{IssuerURL: "https://a", FakeJWT: "jwt-a"})
	hc.setServing()
	if err := hc.check(); err != nil {
		t.Fatal(err)
	}
	rec := cap.Only(t, logging.EventReadinessProxyReady)
	if rec.String("readiness_mode") != "any" {
		t.Fatalf("%v", rec)
	}
}

// TestStalePendingResultIsDroppedOnceInitialized pins the ordering guard for
// concurrent checks. Two checks can snapshot the same issuer as uninitialized;
// if the first records it initialized, the second still holds a pending result
// that is now stale and must not be published after the initialized record,
// nor hold readiness back.
func TestStalePendingResultIsDroppedOnceInitialized(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)
	hc := newTestHealthCheckWithLogger(t, root, true, nil,
		IssuerReadiness{IssuerURL: "https://a", FakeJWT: "jwt-a"})

	hc.mu.Lock()
	hc.initialized["https://a"] = true
	pending := hc.recordProbeResults(context.Background(), nil,
		[]pendingIssuer{{issuerURL: "https://a", reason: pendingNotInitialized}})
	hc.mu.Unlock()

	if len(pending) != 0 {
		t.Fatalf("stale pending result kept: %v", pending)
	}
	if got := cap.ByEvent(logging.EventOIDCIssuerPending); len(got) != 0 {
		t.Fatalf("pending published after initialized: %v", got)
	}
}
