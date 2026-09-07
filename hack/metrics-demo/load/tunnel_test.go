// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The forward's lifecycle is the one part of this program that can outlive it:
// every kubectl it starts is a child process, and the only thing that stops
// one is a stop() the tunnel is still holding. These tests drive that
// lifecycle against a kubectl stand-in on PATH, the way
// hack/verify-portforward.sh does for the shell helper, so no cluster is
// needed and a leak is a test failure rather than something noticed later in
// `ps`.

// stubKubectl puts a kubectl stand-in first on PATH and points it at a
// scratch directory it records itself in: one line per invocation in `n`, one
// pid per invocation in `pids`.
func stubKubectl(t *testing.T, script string) string {
	t.Helper()

	dir := t.TempDir()
	// #nosec G306 -- the stub has to be executable, and it lives in this
	// test's own temporary directory.
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write the kubectl stub: %s", err)
	}
	t.Setenv("PF_STUB_DIR", dir)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return dir
}

// The pid is recorded before the invocation counter, so a stub killed early
// in its own startup - which is exactly what the readiness-timeout case does -
// is still accounted for, and a test that has seen the counter reach N knows
// all N pids are on record.
const stubPreamble = `#!/bin/sh
echo $$ >>"$PF_STUB_DIR/pids"
n=$(cat "$PF_STUB_DIR/n" 2>/dev/null || echo 0)
n=$((n + 1))
printf '%s' "$n" >"$PF_STUB_DIR/n"
`

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// waitForStubs blocks until the stub has been invoked at least want times.
func waitForStubs(t *testing.T, dir string, want int) {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(filepath.Join(dir, "n"))
		if err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n >= want {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the kubectl stub was not invoked %d times within the timeout", want)
}

// assertNoStubsRunning fails if any process the stub started is still alive.
func assertNoStubsRunning(t *testing.T, dir string) {
	t.Helper()

	// The stub records its pid as its first act, but "first act" still comes
	// after the shell has started, so give it a moment rather than reading a
	// file that is about to exist.
	var b []byte
	var err error
	for deadline := time.Now().Add(5 * time.Second); ; {
		if b, err = os.ReadFile(filepath.Join(dir, "pids")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the kubectl stub recorded no pids: %s", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var pids []int
	for _, line := range strings.Fields(string(b)) {
		pid, err := strconv.Atoi(line)
		if err != nil {
			t.Fatalf("the kubectl stub recorded %q as a pid", line)
		}
		pids = append(pids, pid)
	}
	if len(pids) == 0 {
		t.Fatal("the kubectl stub recorded no pids")
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		var alive []int
		for _, pid := range pids {
			if err := syscall.Kill(pid, syscall.Signal(0)); err == nil {
				alive = append(alive, pid)
			}
		}
		if len(alive) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("kubectl port-forward processes %v were left running", alive)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestTunnelCloseDuringReconnect: the waiter goroutine used to call reopen
// synchronously before releasing the channel stop() waits on, and reopen
// retried an open() whose port read had no deadline. Close therefore queued
// behind a reconnect that could not finish, and the run hung on the deferred
// Close instead of exiting.
func TestTunnelCloseDuringReconnect(t *testing.T) {
	dir := stubKubectl(t, stubPreamble+`
if [ "$n" -eq 1 ]; then
  # Comes up, then dies the way kubectl does when a client disappears
  # mid-stream - which is what makes the tunnel reconnect.
  echo "Forwarding from 127.0.0.1:40001 -> 8443"
  sleep 0.2
  exit 1
fi
# Every reconnect hangs without ever announcing a port.
exec sleep 60
`)

	tun, err := newTunnel(context.Background(), "kubeconfig", "proxy", "svc/kop", 8443, "https", testLogger())
	if err != nil {
		t.Fatalf("newTunnel: %s", err)
	}

	// Close must race a reconnect that has really started a kubectl, not an
	// idle tunnel.
	waitForStubs(t, dir, 2)

	done := make(chan struct{})
	go func() {
		tun.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Close did not return while a reconnect was in flight")
	}

	assertNoStubsRunning(t, dir)
}

// TestTunnelDoesNotPublishAPortAfterClose: Close takes the stop it knows
// about and never looks again, so a forward that finished starting just after
// it must be stopped, not published. Publishing it left a kubectl nobody held
// a stop for.
func TestTunnelDoesNotPublishAPortAfterClose(t *testing.T) {
	dir := stubKubectl(t, stubPreamble+`
echo "Forwarding from 127.0.0.1:40002 -> 8443"
exec sleep 60
`)

	tun := &tunnel{
		kubeconfig: "kubeconfig",
		namespace:  "proxy",
		target:     "svc/kop",
		remote:     8443,
		scheme:     "https",
		logger:     testLogger(),
		ready:      10 * time.Second,
	}
	tun.ctx, tun.cancel = context.WithCancel(context.Background())
	t.Cleanup(tun.cancel)
	// Close has run; this forward started just before its cancel landed.
	tun.closed = true

	switch err := tun.open(); {
	case err == nil:
		t.Fatal("open published a port on a closed tunnel")
	case !errors.Is(err, errTunnelClosed):
		t.Fatalf("open on a closed tunnel = %v, want errTunnelClosed", err)
	}
	if tun.port != 0 || tun.stop != nil {
		t.Fatalf("open recorded port %d and stop %v on a closed tunnel", tun.port, tun.stop != nil)
	}

	assertNoStubsRunning(t, dir)
}

// TestPortForwardReadinessTimesOut: reading kubectl's announcement had no
// deadline, so a kubectl that never announces a port - the pod gone, the
// upgrade refused - blocked the caller for ever and left the process behind.
func TestPortForwardReadinessTimesOut(t *testing.T) {
	dir := stubKubectl(t, stubPreamble+`
exec sleep 60
`)

	// Short enough that the test is quick, long enough that the stub shell has
	// certainly started on a loaded machine - the assertion is that the wait
	// ends at all, not that it ends in a particular millisecond.
	const ready = 2 * time.Second

	start := time.Now()
	_, stop, err := startPortForward(context.Background(), "kubeconfig", "proxy", "svc/kop", 8443,
		ready, func(error) {})
	if err == nil {
		stop()
		t.Fatal("startPortForward returned no error for a kubectl that never announced a port")
	}
	if !strings.Contains(err.Error(), "did not announce a local port") {
		t.Fatalf("startPortForward error = %q, want it to name the missing announcement", err)
	}
	if elapsed := time.Since(start); elapsed > 10*ready {
		t.Fatalf("startPortForward took %s to give up on a %s readiness timeout", elapsed, ready)
	}

	assertNoStubsRunning(t, dir)
}
