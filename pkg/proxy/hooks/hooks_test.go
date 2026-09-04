// Copyright Jetstack Ltd. See LICENSE for details.
package hooks

import (
	"errors"
	"log/slog"
	"reflect"
	"testing"
	"time"
)

// TestRunPreShutdownHooksDoesNotHoldLock is the regression test for #54: a hook
// must not run while the registry lock is held, otherwise a slow or blocking
// hook stalls every other registry operation and a hook that touches the
// registry deadlocks. We register a hook that blocks until released and assert
// that AddPreShutdownHook (which needs the lock) still returns promptly while
// the hook is mid-flight.
func TestRunPreShutdownHooksDoesNotHoldLock(t *testing.T) {
	h := New(slog.New(slog.DiscardHandler))

	entered := make(chan struct{})
	release := make(chan struct{})
	h.AddPreShutdownHook("blocking", func() error {
		close(entered)
		<-release
		return nil
	})

	runDone := make(chan error, 1)
	go func() { runDone <- h.RunPreShutdownHooks() }()

	// Wait until the blocking hook is executing.
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("blocking hook never started")
	}

	// The lock must be free while the hook runs: registering another hook must
	// not block. If the lock were held across hook execution this would hang.
	addDone := make(chan struct{})
	go func() {
		h.AddPreShutdownHook("added-during-run", func() error { return nil })
		close(addDone)
	}()

	select {
	case <-addDone:
	case <-time.After(2 * time.Second):
		t.Fatal("AddPreShutdownHook blocked while a hook was running: lock held across hook execution")
	}

	// Let the blocking hook finish and confirm the run completes without error.
	close(release)
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("unexpected error from RunPreShutdownHooks: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunPreShutdownHooks did not complete after hook released")
	}
}

// TestRunPreShutdownHooksOrderAndContinuation verifies hooks run in registration
// order and that one hook's failure does not prevent later hooks from running.
func TestRunPreShutdownHooksOrderAndContinuation(t *testing.T) {
	h := New(slog.New(slog.DiscardHandler))

	var order []string
	errBoom := errors.New("boom")

	h.AddPreShutdownHook("first", func() error {
		order = append(order, "first")
		return nil
	})
	h.AddPreShutdownHook("second", func() error {
		order = append(order, "second")
		return errBoom
	})
	h.AddPreShutdownHook("third", func() error {
		order = append(order, "third")
		return nil
	})

	err := h.RunPreShutdownHooks()

	if want := []string{"first", "second", "third"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("hooks ran out of order or a hook was skipped: got %v want %v", order, want)
	}
	if err == nil {
		t.Fatal("expected an aggregate error from the failing hook, got nil")
	}
	// The wrapped cause must remain inspectable through the aggregate via %w.
	if !errors.Is(err, errBoom) {
		t.Fatalf("errors.Is could not reach wrapped cause through aggregate: %v", err)
	}
}

// TestAddPreShutdownHookOverwritesInPlace verifies that re-registering a name
// replaces the hook while preserving its original position (last write wins).
func TestAddPreShutdownHookOverwritesInPlace(t *testing.T) {
	h := New(slog.New(slog.DiscardHandler))

	var order []string
	h.AddPreShutdownHook("a", func() error { order = append(order, "a-old"); return nil })
	h.AddPreShutdownHook("b", func() error { order = append(order, "b"); return nil })
	// Overwrite "a": it must keep its original (first) position but run the new
	// callback.
	h.AddPreShutdownHook("a", func() error { order = append(order, "a-new"); return nil })

	if err := h.RunPreShutdownHooks(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if want := []string{"a-new", "b"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("overwrite did not preserve position / replace callback: got %v want %v", order, want)
	}
}

// TestRunPreShutdownHooksNoHooks verifies the empty registry runs cleanly.
func TestRunPreShutdownHooksNoHooks(t *testing.T) {
	if err := New(slog.New(slog.DiscardHandler)).RunPreShutdownHooks(); err != nil {
		t.Fatalf("expected nil error with no hooks, got %v", err)
	}
}
