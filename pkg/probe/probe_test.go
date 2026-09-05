// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
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
	// Discarding loggers by default: NewServer never leaves either nil, and a
	// test that asserts on records replaces them via newTestHealthCheckWithLogger.
	return &HealthCheck{
		readinessLogger: slog.New(slog.DiscardHandler),
		oidcLogger:      slog.New(slog.DiscardHandler),
		oidcAuther:      auther,
		issuers:         issuers,
		requireAll:      requireAll,
		initialized:     make(map[string]bool),
	}
}

func newTestHealthCheck(requireAll bool, notInit map[string]bool, issuers ...IssuerReadiness) *HealthCheck {
	return newTestHealthCheckWithAuther(requireAll, &fakeAuther{notInit: notInit}, issuers...)
}

// newTestHealthCheckWithLogger builds a HealthCheck reporting through root.
// notInit is keyed by issuer URL rather than by fake JWT, which is what a test
// asserting on records cares about; the translation to the token keying
// fakeAuther uses happens here.
func newTestHealthCheckWithLogger(t testing.TB, root *slog.Logger, requireAll bool, notInit map[string]bool, issuers ...IssuerReadiness) *HealthCheck {
	t.Helper()

	notInitByToken := make(map[string]bool, len(notInit))
	for _, issuer := range issuers {
		if notInit[issuer.IssuerURL] {
			notInitByToken[issuer.FakeJWT] = true
		}
	}

	h := newTestHealthCheckWithAuther(requireAll, &fakeAuther{notInit: notInitByToken}, issuers...)
	h.readinessLogger = logging.ForComponent(root, logging.ComponentReadiness)
	h.oidcLogger = logging.ForComponent(root, logging.ComponentOIDC)
	return h
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
			// This table covers issuer readiness, so open the serving gate;
			// TestCheckNotReadyBeforeServing covers the gate itself.
			h.SetServing()
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

// TestCheckNotReadyBeforeServing verifies the serving gate: even with every
// issuer initialized, readiness stays false until the proxy is actually
// serving. An initialized issuer on a process that is not yet answering
// requests is not readiness.
func TestCheckNotReadyBeforeServing(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	h := newTestHealthCheck(true, nil, issuerA)

	err := h.Check()
	if err == nil {
		t.Fatal("expected not-ready before the proxy is serving, got nil")
	}
	if !strings.Contains(err.Error(), "serving") {
		t.Fatalf("expected the error to name the serving condition, got: %v", err)
	}
	if h.ready {
		t.Fatal("readiness must not latch before the proxy is serving")
	}
}

// TestCheckReadyAfterServing verifies the gate opens: the same health check
// that reports not-ready before serving reports ready once SetServing is
// called, so the gate delays readiness rather than blocking it permanently.
func TestCheckReadyAfterServing(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	h := newTestHealthCheck(true, nil, issuerA)

	if err := h.Check(); err == nil {
		t.Fatal("expected not-ready before the proxy is serving, got nil")
	}

	h.SetServing()
	if err := h.Check(); err != nil {
		t.Fatalf("expected ready once serving with the issuer initialized, got: %v", err)
	}
}

// TestReadyEndpointReportsNotServing verifies the gate is visible over HTTP:
// /ready answers 503 and names the serving condition, so an operator reading
// the probe response can tell why the pod is held back.
func TestReadyEndpointReportsNotServing(t *testing.T) {
	h := newTestHealthCheck(false, nil,
		IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"})
	handler := h.handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /ready before serving: got %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), "serving") {
		t.Fatalf("expected the body to name the serving condition, got: %q", rec.Body.String())
	}

	// Liveness is not gated: the process is alive well before it serves, and
	// gating it would invite the kubelet to restart the pod during startup.
	liveRec := httptest.NewRecorder()
	handler.ServeHTTP(liveRec, httptest.NewRequest(http.MethodGet, "/live", nil))
	if liveRec.Code != http.StatusOK {
		t.Fatalf("GET /live before serving: got %d, want %d", liveRec.Code, http.StatusOK)
	}

	// Once serving, the same endpoint reports ready.
	h.SetServing()
	readyRec := httptest.NewRecorder()
	handler.ServeHTTP(readyRec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if readyRec.Code != http.StatusOK {
		t.Fatalf("GET /ready after serving: got %d, want %d", readyRec.Code, http.StatusOK)
	}
}

func TestCheckReadinessIsSticky(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	notInit := map[string]bool{}
	h := newTestHealthCheck(false, notInit, issuerA)
	h.SetServing()

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
	h.SetServing()
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
	h.SetServing()

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
			h.SetServing()

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

// TestHandlerRejectsNonGET verifies the readiness/liveness endpoints answer GET
// but reject other methods with 405, preserving the previous handler's contract.
func TestHandlerRejectsNonGET(t *testing.T) {
	h := newTestHealthCheck(false, nil,
		IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"})
	// Serving, so GET /ready exercises the readiness path rather than the gate.
	h.SetServing()
	handler := h.handler()

	for _, path := range []string{"/live", "/ready"} {
		getReq := httptest.NewRequest(http.MethodGet, path, nil)
		getRec := httptest.NewRecorder()
		handler.ServeHTTP(getRec, getReq)
		if getRec.Code == http.StatusMethodNotAllowed {
			t.Fatalf("GET %s: unexpected 405", path)
		}

		postReq := httptest.NewRequest(http.MethodPost, path, nil)
		postRec := httptest.NewRecorder()
		handler.ServeHTTP(postRec, postReq)
		if postRec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s: got %d, want %d", path, postRec.Code, http.StatusMethodNotAllowed)
		}
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

	s := NewServer(port, nil, false, &fakeAuther{}, slog.New(slog.DiscardHandler))
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

	s := NewServer(port, nil, false, &fakeAuther{}, slog.New(slog.DiscardHandler))
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
		s := NewServer(port, nil, false, &fakeAuther{}, slog.New(slog.DiscardHandler))
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
	// Check returns before reaching the authenticator unless it is serving.
	h.SetServing()

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
	hc.SetServing()
	_ = hc.Check()
	_ = hc.Check()
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
	hc.SetServing()
	if err := hc.Check(); err != nil {
		t.Fatal(err)
	}
	rec := cap.Only(t, logging.EventReadinessProxyReady)
	if rec.String("readiness_mode") != "any" {
		t.Fatalf("%v", rec)
	}
}

// TestIssuerNameNeverEmitsRawInput pins the binding constraint that a full
// issuer URL never reaches the log stream. A value the URL parser cannot turn
// into a host must degrade to a fixed placeholder, not to the input itself:
// falling back to the raw string is exactly the leak the constraint forbids.
func TestIssuerNameNeverEmitsRawInput(t *testing.T) {
	tests := map[string]struct {
		issuerURL string
		want      string
	}{
		"host is kept":           {issuerURL: "https://idp.example.com/realms/corp", want: "idp.example.com"},
		"host with port":         {issuerURL: "https://idp.example.com:8443/", want: "idp.example.com:8443"},
		"no scheme, no host":     {issuerURL: "idp.example.com/realms/corp", want: "unknown"},
		"unparsable":             {issuerURL: "https://exa mple.com/%zz", want: "unknown"},
		"control characters":     {issuerURL: "not a url\nissuer=secret", want: "unknown"},
		"empty":                  {issuerURL: "", want: "unknown"},
		"opaque scheme, no host": {issuerURL: "mailto:idp@example.com", want: "unknown"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := IssuerName(tc.issuerURL)
			if got != tc.want {
				t.Fatalf("IssuerName(%q) = %q, want %q", tc.issuerURL, got, tc.want)
			}
			// The stronger property: whatever the input, the output is either a
			// bare host or the placeholder. It is never the input.
			if got != "unknown" && got == tc.issuerURL {
				t.Fatalf("IssuerName(%q) returned its own input", tc.issuerURL)
			}
		})
	}
}

// TestReadinessServerFailedOnShutdownError drives the probe listener's error
// path: a request still in flight when the context is cancelled keeps the
// graceful shutdown from completing within its timeout, and that failure must
// be reported rather than swallowed.
func TestReadinessServerFailedOnShutdownError(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)

	port := freePort(t)
	s := NewServer(port, nil, false, &fakeAuther{}, root)

	// A handler that holds the connection open for longer than the shutdown
	// budget, so Shutdown returns its context's deadline error.
	inFlight := make(chan struct{})
	release := make(chan struct{})
	s.srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(inFlight)
		<-release
		w.WriteHeader(http.StatusOK)
	})
	s.shutdownTimeout = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %s", err)
	}

	go func() {
		//nolint:errcheck // the response never arrives; the request is only here to hold the connection.
		http.Get("http://127.0.0.1:" + port + "/live")
	}()
	<-inFlight

	cancel()

	// Wait for the failure record rather than for a fixed duration.
	deadline := time.After(5 * time.Second)
	for len(cap.ByEvent(logging.EventReadinessServerFailed)) == 0 {
		select {
		case <-deadline:
			t.Fatalf("no readiness.server.failed record: %s", cap.Raw())
		case <-time.After(10 * time.Millisecond):
		}
	}

	rec := cap.ByEvent(logging.EventReadinessServerFailed)[0]
	if rec.String("level") != "ERROR" || rec.String("error_message") == "" {
		t.Fatalf("%v", rec)
	}
	if rec.String("component") != string(logging.ComponentReadiness) {
		t.Fatalf("component = %q, want readiness", rec.String("component"))
	}

	close(release)
	_ = s.Shutdown()
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
