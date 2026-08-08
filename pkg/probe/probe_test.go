// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// fakeAuther simulates the union authenticator: tokens listed in notInit
// hit an issuer whose JWKS is not yet fetched; every other token reaches
// an initialized issuer and fails ordinary verification. A per-token error
// may be supplied via override to model alternate phrasings and transient
// failures.
type fakeAuther struct {
	mu       sync.Mutex
	notInit  map[string]bool
	override map[string]error
	calls    map[string]int
}

func (f *fakeAuther) AuthenticateToken(_ context.Context, token string) (*authenticator.Response, bool, error) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = make(map[string]int)
	}
	f.calls[token]++
	f.mu.Unlock()

	if err, ok := f.override[token]; ok {
		return nil, false, err
	}
	if f.notInit[token] {
		return nil, false, errors.New("oidc: authenticator not initialized")
	}
	return nil, false, errors.New("oidc: verify token: signature invalid")
}

func (f *fakeAuther) callCount(token string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[token]
}

func newTestHealthCheckWithAuther(requireAll bool, auther authenticator.Token, issuers ...IssuerReadiness) *HealthCheck {
	return &HealthCheck{
		oidcAuther:  auther,
		issuers:     issuers,
		requireAll:  requireAll,
		initialized: make(map[string]bool),
	}
}

func newTestHealthCheck(requireAll bool, notInit map[string]bool, issuers ...IssuerReadiness) *HealthCheck {
	return newTestHealthCheckWithAuther(requireAll, &fakeAuther{notInit: notInit}, issuers...)
}

func TestCheckReadiness(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	issuerB := IssuerReadiness{IssuerURL: "https://b.example.com", FakeJWT: "jwt-b"}

	tests := []struct {
		name       string
		requireAll bool
		notInit    map[string]bool
		wantReady  bool
	}{
		{
			name:       "default mode: one of two initialized is ready",
			requireAll: false,
			notInit:    map[string]bool{"jwt-b": true},
			wantReady:  true,
		},
		{
			name:       "default mode: none initialized is not ready",
			requireAll: false,
			notInit:    map[string]bool{"jwt-a": true, "jwt-b": true},
			wantReady:  false,
		},
		{
			name:       "require-all: one pending is not ready",
			requireAll: true,
			notInit:    map[string]bool{"jwt-b": true},
			wantReady:  false,
		},
		{
			name:       "require-all: all initialized is ready",
			requireAll: true,
			notInit:    map[string]bool{},
			wantReady:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHealthCheck(tc.requireAll, tc.notInit, issuerA, issuerB)
			err := h.Check()
			if tc.wantReady && err != nil {
				t.Fatalf("expected ready, got error: %v", err)
			}
			if !tc.wantReady && err == nil {
				t.Fatal("expected not ready, got nil error")
			}
		})
	}
}

func TestCheckReadinessIsSticky(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	notInit := map[string]bool{}
	h := newTestHealthCheck(false, notInit, issuerA)

	if err := h.Check(); err != nil {
		t.Fatalf("expected ready, got: %v", err)
	}

	// Simulate the issuer regressing to uninitialized: readiness must stick.
	notInit["jwt-a"] = true
	if err := h.Check(); err != nil {
		t.Fatalf("expected readiness to be sticky, got: %v", err)
	}
}

// TestCheckContinuesProbingPendingAfterLatch verifies that once readiness
// latches (default mode, one of two issuers initialized), subsequent Check
// calls still return nil AND still probe the still-pending issuer so it can
// transition to initialized and be logged, while the already-initialized
// issuer is not re-probed.
func TestCheckContinuesProbingPendingAfterLatch(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	issuerB := IssuerReadiness{IssuerURL: "https://b.example.com", FakeJWT: "jwt-b"}

	notInit := map[string]bool{"jwt-b": true}
	h := newTestHealthCheck(false, notInit, issuerA, issuerB)
	fake := h.oidcAuther.(*fakeAuther)

	if err := h.Check(); err != nil {
		t.Fatalf("expected ready (issuer A initialized), got: %v", err)
	}
	if !h.ready {
		t.Fatal("expected readiness to have latched")
	}

	aCallsAfterFirst := fake.callCount("jwt-a")
	bCallsAfterFirst := fake.callCount("jwt-b")
	if aCallsAfterFirst != 1 || bCallsAfterFirst != 1 {
		t.Fatalf("expected 1 call each after first Check, got a=%d b=%d", aCallsAfterFirst, bCallsAfterFirst)
	}

	// Second Check: readiness already latched, so it must return nil
	// regardless of issuer B still being pending, but issuer B must still
	// be probed (call count increases) while issuer A (already
	// initialized) must not be re-probed.
	if err := h.Check(); err != nil {
		t.Fatalf("expected nil error once latched even with issuer B pending, got: %v", err)
	}

	if got := fake.callCount("jwt-a"); got != aCallsAfterFirst {
		t.Fatalf("expected initialized issuer A not to be re-probed, call count changed from %d to %d", aCallsAfterFirst, got)
	}
	if got := fake.callCount("jwt-b"); got <= bCallsAfterFirst {
		t.Fatalf("expected pending issuer B to still be probed, call count did not increase (still %d)", got)
	}

	// Now let issuer B initialize and confirm the transition is picked up
	// and it is subsequently no longer re-probed either.
	delete(notInit, "jwt-b")
	if err := h.Check(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	bCallsAfterInit := fake.callCount("jwt-b")

	if err := h.Check(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if got := fake.callCount("jwt-b"); got != bCallsAfterInit {
		t.Fatalf("expected issuer B not to be re-probed once initialized, call count changed from %d to %d", bCallsAfterInit, got)
	}
}

// TestCheckAlternatePhrasingKeepsPending verifies that the alternate upstream
// wording "... is not initialized" is still recognised as pending and does not
// falsely latch readiness.
func TestCheckAlternatePhrasingKeepsPending(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}

	auther := &fakeAuther{
		override: map[string]error{
			"jwt-a": errors.New("oidc: authenticator for issuer is not initialized"),
		},
	}
	h := newTestHealthCheckWithAuther(true, auther, issuerA)

	if err := h.Check(); err == nil {
		t.Fatal("expected not-ready for alternate 'is not initialized' phrasing, got nil")
	}
	if h.ready {
		t.Fatal("readiness must not latch while the only issuer is uninitialized")
	}
	if h.initialized[issuerA.IssuerURL] {
		t.Fatal("issuer must not be marked initialized for a 'not initialized' error")
	}
}

// TestCheckTransientErrorDoesNotLatch verifies that a transient network/timeout
// error leaves the issuer pending instead of being mistaken for a fetched JWKS
// (which would falsely latch readiness).
func TestCheckTransientErrorDoesNotLatch(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}

	tests := map[string]error{
		"context deadline":    context.DeadlineExceeded,
		"connection refused":  errors.New(`Get "https://a.example.com/.well-known/openid-configuration": dial tcp 10.0.0.1:443: connect: connection refused`),
		"net timeout wrapped": &net.OpError{Op: "dial", Err: timeoutError{}},
	}

	for name, retErr := range tests {
		t.Run(name, func(t *testing.T) {
			auther := &fakeAuther{override: map[string]error{"jwt-a": retErr}}
			h := newTestHealthCheckWithAuther(true, auther, issuerA)

			if err := h.Check(); err == nil {
				t.Fatal("expected not-ready for transient error, got nil")
			}
			if h.ready {
				t.Fatal("readiness must not latch on a transient error")
			}
			if h.initialized[issuerA.IssuerURL] {
				t.Fatal("issuer must not be marked initialized on a transient error")
			}
		})
	}
}

// timeoutError is a net.Error whose Timeout reports true, modelling a wrapped
// i/o timeout surfaced through errors.As.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// freePort reserves and immediately releases a wildcard port, returning its
// number for a subsequent bind. Server.Start binds 0.0.0.0, so reserve 0.0.0.0.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("splitting host/port: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("releasing reserved port: %v", err)
	}
	return port
}

// TestServerStartReturnsBindError verifies Start surfaces a bind failure to the
// caller synchronously rather than swallowing it inside a goroutine.
func TestServerStartReturnsBindError(t *testing.T) {
	occupied, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	_, port, err := net.SplitHostPort(occupied.Addr().String())
	if err != nil {
		t.Fatalf("splitting host/port: %v", err)
	}

	s := NewServer(port, nil, false, &fakeAuther{})
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("expected Start to return an error binding an occupied port, got nil")
	}
}

// TestServerStartServesAndShutsDown verifies the full lifecycle: the server
// serves after Start, stops when its context is cancelled, Wait returns nil for
// the graceful shutdown, and the listener is released (proving the documented
// stop path actually frees the port).
func TestServerStartServesAndShutsDown(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := NewServer(port, nil, false, &fakeAuther{})
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start returned unexpected error: %v", err)
	}

	// The liveness endpoint has no checks, so it returns 200 once serving.
	url := "http://127.0.0.1:" + port + "/live"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("readiness server not serving after Start: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status from /live: got %d want %d", resp.StatusCode, http.StatusOK)
	}

	// Cancelling the context must trigger a graceful shutdown; Wait then returns
	// the normalized (nil) serve error.
	cancel()
	if err := s.Wait(); err != nil {
		t.Fatalf("Wait returned unexpected error after graceful shutdown: %v", err)
	}

	// The listener must be released: rebinding the same port must now succeed.
	ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
	if err != nil {
		t.Fatalf("listener not released after shutdown, rebind failed: %v", err)
	}
	_ = ln.Close()
}

// TestServerNoGoroutineLeak verifies repeated Start/shutdown cycles do not leak
// goroutines (the serve and context-watcher goroutines must both exit).
func TestServerNoGoroutineLeak(t *testing.T) {
	// Let any goroutines from earlier tests settle first.
	baseline := stableGoroutines(t)

	for i := 0; i < 20; i++ {
		port := freePort(t)
		ctx, cancel := context.WithCancel(context.Background())
		s := NewServer(port, nil, false, &fakeAuther{})
		if err := s.Start(ctx); err != nil {
			cancel()
			t.Fatalf("Start returned unexpected error: %v", err)
		}
		cancel()
		if err := s.Wait(); err != nil {
			t.Fatalf("Wait returned unexpected error: %v", err)
		}
	}

	if got := stableGoroutines(t); got > baseline {
		t.Fatalf("goroutine leak across Start/shutdown cycles: baseline=%d got=%d", baseline, got)
	}
}

// stableGoroutines polls until the goroutine count stops decreasing, returning
// the settled value. This avoids flakiness from goroutines still winding down.
func stableGoroutines(t *testing.T) int {
	t.Helper()
	prev := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		cur := runtime.NumGoroutine()
		if cur >= prev {
			return prev
		}
		prev = cur
	}
	return prev
}

// concurrentAuther records the maximum number of AuthenticateToken calls in
// flight simultaneously. It is used to prove the health-check lock is not held
// across the authenticator call (#53).
type concurrentAuther struct {
	mu      sync.Mutex
	current int
	max     int

	entered chan struct{}
	release chan struct{}
}

func (c *concurrentAuther) AuthenticateToken(_ context.Context, _ string) (*authenticator.Response, bool, error) {
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

func (c *concurrentAuther) maxConcurrent() int {
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
	auther := &concurrentAuther{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	h := newTestHealthCheckWithAuther(true, auther, issuerA)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.Check()
		}()
	}

	// Both Check calls must reach the authenticator concurrently.
	for i := 0; i < 2; i++ {
		select {
		case <-auther.entered:
		case <-time.After(2 * time.Second):
			close(auther.release)
			t.Fatal("only one Check reached the authenticator: lock held across auth call")
		}
	}

	close(auther.release)
	wg.Wait()

	if got := auther.maxConcurrent(); got < 2 {
		t.Fatalf("expected >=2 concurrent authenticator calls, got %d", got)
	}
}
