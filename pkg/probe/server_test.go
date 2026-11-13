// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

// freePort reserves and immediately releases a wildcard port, returning its
// number for a subsequent bind. Server.Start binds 0.0.0.0, so reserve 0.0.0.0.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("releasing reserved port: %v", err)
	}
	return ln.Addr().(*net.TCPAddr).Port
}

// TestServerStartReturnsBindError verifies Start surfaces a bind failure to the
// caller synchronously rather than swallowing it inside a goroutine.
func TestServerStartReturnsBindError(t *testing.T) {
	occupied, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	port := occupied.Addr().(*net.TCPAddr).Port

	s := NewServer(port, nil, false, &fakeAuthenticator{}, slog.New(slog.DiscardHandler))
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

	s := NewServer(port, nil, false, &fakeAuthenticator{}, slog.New(slog.DiscardHandler))
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start returned unexpected error: %v", err)
	}

	// The liveness endpoint has no checks, so it returns 200 once serving.
	url := fmt.Sprintf("http://127.0.0.1:%d/live", port)
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
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
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
		s := NewServer(port, nil, false, &fakeAuthenticator{}, slog.New(slog.DiscardHandler))
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

// TestReadinessServerFailedOnShutdownError drives the probe listener's error
// path: a request still in flight when the context is cancelled keeps the
// graceful shutdown from completing within its timeout, and that failure must
// be reported rather than swallowed.
func TestReadinessServerFailedOnShutdownError(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)

	port := freePort(t)
	s := NewServer(port, nil, false, &fakeAuthenticator{}, root)

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
		http.Get(fmt.Sprintf("http://127.0.0.1:%d/live", port))
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

// TestReadinessServerWaitReturnsTheShutdownError pins that a drain which
// overruns its budget reaches the caller, not just the log stream. cmd/app
// joins Wait's result into the process exit error, so a readiness listener
// that never released its port has to be reportable there.
func TestReadinessServerWaitReturnsTheShutdownError(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)

	port := freePort(t)
	s := NewServer(port, nil, false, &fakeAuthenticator{}, root)

	// A handler that outlives the shutdown budget, so Shutdown returns its
	// context's deadline error.
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
		http.Get(fmt.Sprintf("http://127.0.0.1:%d/live", port))
	}()
	<-inFlight

	cancel()

	err := s.Wait()
	close(release)
	if err == nil {
		t.Fatal("Wait returned nil after a shutdown that overran its budget")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait error = %v, want the shutdown deadline", err)
	}
}

// TestReadinessServerWaitBlocksUntilShutdownCompletes pins that Wait reports
// the end of the drain, not the end of Serve. Shutdown makes Serve return at
// once, so a Wait that keys on Serve alone lets cmd/app run the pre-shutdown
// hooks while the readiness port is still held by an in-flight request.
func TestReadinessServerWaitBlocksUntilShutdownCompletes(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)

	port := freePort(t)
	s := NewServer(port, nil, false, &fakeAuthenticator{}, root)

	// The handler stays in flight well past the cancellation and only then
	// lets the connection go idle, which is what Shutdown waits for. The
	// budget is left at its default so the drain succeeds.
	inFlight := make(chan struct{})
	var handlerReturned atomic.Bool
	s.srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(inFlight)
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		handlerReturned.Store(true)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %s", err)
	}

	go func() {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/live", port))
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-inFlight

	cancel()

	if err := s.Wait(); err != nil {
		t.Fatalf("Wait: %s", err)
	}
	if !handlerReturned.Load() {
		t.Fatal("Wait returned while a request was still in flight")
	}
}
