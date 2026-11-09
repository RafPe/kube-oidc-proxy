// Copyright Jetstack Ltd. See LICENSE for details.
package signals

import (
	"context"
	"log/slog"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

// waitFor blocks until cond holds or the test's patience runs out. The signal
// handler runs in its own goroutine, so every assertion here is about state
// that appears asynchronously.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.After(5 * time.Second)
	for !cond() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(time.Millisecond):
		}
	}
}

// TestHandlerReportsFirstSignalThenForcedExit drives the whole signal sequence
// through the injectable seam rather than by signalling the test process: the
// first signal reports the graceful shutdown, the repeats are absorbed
// silently, and the one after them reports the forced exit.
func TestHandlerReportsFirstSignalThenForcedExit(t *testing.T) {
	root, cap := logtest.New(t, 0)

	ch := make(chan os.Signal, 8)
	exited := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	watchSignals(logging.ForComponent(root, logging.ComponentShutdown), ch, cancel, func() { close(exited) })

	ch <- syscall.SIGTERM

	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the context was not cancelled on the first signal")
	}

	waitFor(t, "the first shutdown record", func() bool {
		return len(cap.ByEvent(logging.EventProxyShutdownStarted)) == 1
	})

	first := cap.ByEvent(logging.EventProxyShutdownStarted)[0]
	if first.String("signal") != "SIGTERM" {
		t.Fatalf("signal = %q, want SIGTERM", first.String("signal"))
	}
	if first.String("level") != "INFO" {
		t.Fatalf("level = %q, want INFO", first.String("level"))
	}
	if _, ok := first["forced"]; ok {
		t.Fatalf("the first record must not be forced: %v", first)
	}

	// The signals absorbed while the graceful teardown runs say nothing new,
	// so they must not each produce a record.
	for i := 0; i < forcedSignalCount-1; i++ {
		ch <- syscall.SIGTERM
	}
	if got := len(cap.ByEvent(logging.EventProxyShutdownStarted)); got != 1 {
		t.Fatalf("repeated signals produced %d records, want 1", got)
	}

	// The signal after the absorbed ones forces the exit.
	ch <- syscall.SIGINT

	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the forced exit was never taken")
	}

	waitFor(t, "the forced shutdown record", func() bool {
		return len(cap.ByEvent(logging.EventProxyShutdownStarted)) == 2
	})

	forced := cap.ByEvent(logging.EventProxyShutdownStarted)[1]
	if forced.String("signal") != "SIGINT" {
		t.Fatalf("signal = %q, want SIGINT", forced.String("signal"))
	}
	if forced["forced"] != true {
		t.Fatalf("forced = %v, want true: %v", forced["forced"], forced)
	}
}

// TestSignalName pins the two contract values. A raw signal renders as its
// description ("terminated", "interrupt"), which is not what the record carries.
func TestSignalName(t *testing.T) {
	if got := signalName(syscall.SIGTERM); got != "SIGTERM" {
		t.Errorf("signalName(SIGTERM) = %q", got)
	}
	if got := signalName(syscall.SIGINT); got != "SIGINT" {
		t.Errorf("signalName(SIGINT) = %q", got)
	}
}

// TestNotifyContextStopReleasesTheContext pins stop: it cancels the returned
// context without any signal having arrived, and leaves the parent untouched.
func TestNotifyContextStopReleasesTheContext(t *testing.T) {
	parent := context.Background()
	ctx, stop := NotifyContext(parent, slog.New(slog.DiscardHandler))
	if ctx.Err() != nil {
		t.Fatal("context cancelled before any signal")
	}
	stop()
	if ctx.Err() == nil {
		t.Fatal("stop did not release the context")
	}
	if parent.Err() != nil {
		t.Fatal("stop cancelled the parent")
	}
}
