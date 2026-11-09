// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tunnel keeps a kubectl port-forward to the proxy Service open for the life
// of the run. kubectl drops a forward when a client disappears mid-stream
// ("lost connection to pod" after a broken pipe), and this generator does that
// on purpose in the exec and watch scenarios, so the tunnel reopens itself
// instead of turning the rest of the run into "connection refused". The local
// port is whatever kubectl picks, and changes when it reopens: a fixed port
// would silently attach to a forward left behind by an earlier run.
type tunnel struct {
	kubeconfig string
	namespace  string
	target     string
	remote     int
	scheme     string
	logger     *slog.Logger
	ready      time.Duration

	// The tunnel's own context, derived from the caller's and cancelled by
	// Close. A reconnect runs on its own goroutine and a starting kubectl
	// waits on this context, so Close tells them to stop rather than queueing
	// behind them.
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	port   int
	stop   func()
	closed bool
}

// errTunnelClosed is what open() reports when Close ran while the forward it
// started was still coming up. That forward is stopped rather than published:
// Close has already taken the stop it knew about and will never look again, so
// a port published after it belongs to a kubectl nobody can stop.
var errTunnelClosed = errors.New("the tunnel was closed while a port-forward was starting")

func newTunnel(ctx context.Context, kubeconfig, namespace, target string, remote int, scheme string, logger *slog.Logger) (*tunnel, error) {
	t := &tunnel{
		kubeconfig: kubeconfig,
		namespace:  namespace,
		target:     target,
		remote:     remote,
		scheme:     scheme,
		logger:     logger,
		ready:      portForwardReadyTimeout,
	}
	t.ctx, t.cancel = context.WithCancel(ctx)

	if err := t.open(); err != nil {
		t.cancel()

		return nil, err
	}

	// The caller's deferred Close only fires once the caller returns, and a
	// call still in flight would keep every kubectl child alive until it did.
	// A cancelled context - which is what a signal now is - closes the tunnel
	// straight away. Close cancels t.ctx itself, so this goroutine always
	// ends, and Close is idempotent, so both paths may run.
	go func() {
		<-t.ctx.Done()
		t.Close()
	}()

	return t, nil
}

// URL is the far end's address through the tunnel as it stands right now.
func (t *tunnel) URL() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	return fmt.Sprintf("%s://127.0.0.1:%d", t.scheme, t.port)
}

// Close stops the forward and refuses every later one. It is idempotent, so
// the deferred Close in run() and the watchdog that closes on cancellation can
// both call it.
func (t *tunnel) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()

		return
	}
	t.closed = true
	stop := t.stop
	t.stop = nil
	t.mu.Unlock()

	// Cancel before waiting, not after. A reconnect is running on its own
	// goroutine and a starting kubectl is watching this context; stopping the
	// current forward first is how Close used to block for the whole reopen
	// budget behind a kubectl that had not announced a port yet.
	t.cancel()

	if stop != nil {
		stop()
	}
}

func (t *tunnel) closedNow() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.closed
}

func (t *tunnel) open() error {
	port, stop, err := t.startPortForward(
		// On its own goroutine: this callback runs on the one goroutine that
		// owns cmd.Wait, and stop() waits for that goroutine to finish, so a
		// reconnect started here would be something Close has to outlast.
		func(cause error) { go t.reopen(cause) })
	if err != nil {
		return err
	}

	t.mu.Lock()
	closed := t.closed
	if !closed {
		t.port, t.stop = port, stop
	}
	t.mu.Unlock()

	if closed {
		stop()

		return errTunnelClosed
	}

	return nil
}

func (t *tunnel) reopen(cause error) {
	if t.closedNow() {
		return
	}

	t.logger.Warn("port-forward dropped, reopening",
		slog.String("target", t.target),
		slog.String("error_message", cause.Error()))

	for i := 0; i < tunnelReopenAttempts; i++ {
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(time.Second):
		}
		switch err := t.open(); {
		case err == nil:
			t.logger.Info("port-forward reopened",
				slog.String("target", t.target), slog.String("url", t.URL()))

			return
		case errors.Is(err, errTunnelClosed):
			return
		}
	}

	t.logger.Error("port-forward could not be reopened; traffic has stopped",
		slog.String("target", t.target))
}

// portAnnouncement is what the goroutine reading kubectl's stdout reports:
// the local port it announced, or why it never did.
type portAnnouncement struct {
	port int
	err  error
}

// startPortForward runs one kubectl port-forward of t.target and returns the
// local port it chose. It gives up after t.ready if kubectl never announces
// one, and onDeath is called if the forward later exits on its own.
func (t *tunnel) startPortForward(onDeath func(error)) (int, func(), error) {
	ctx := t.ctx
	// #nosec G204 -- the binary is the constant "kubectl"; the variable
	// arguments are the operator's own --state and --namespace flags and a
	// target this program composed from names it read out of the cluster.
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", t.kubeconfig, "-n", t.namespace,
		"port-forward", t.target, fmt.Sprintf(":%d", t.remote))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, nil, err
	}
	stderr := &strings.Builder{}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return 0, nil, fmt.Errorf("failed to start kubectl port-forward: %w", err)
	}

	// The announcement is read on its own goroutine so the wait for it can be
	// bounded. Killing the process closes the pipe, which is what lets that
	// goroutine finish once this one has given up.
	announced := make(chan portAnnouncement, 1)
	go func() {
		port, err := readForwardedPort(stdout)
		announced <- portAnnouncement{port: port, err: err}
	}()

	var port int
	err = nil
	select {
	case a := <-announced:
		port, err = a.port, a.err
	case <-time.After(t.ready):
		err = fmt.Errorf("kubectl port-forward did not announce a local port within %s", t.ready)
	case <-ctx.Done():
		err = fmt.Errorf("kubectl port-forward was stopped before it announced a local port: %w", ctx.Err())
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		return 0, nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}

	// kubectl keeps writing a line per connection. Nothing reads them, so the
	// pipe must be drained or kubectl blocks on a full buffer once the run has
	// made a few hundred calls, and the traffic simply stops.
	go func() { _, _ = io.Copy(io.Discard, stdout) }()

	// Exactly one goroutine may Wait on a command, so this one owns it and
	// stop() waits for it rather than calling Wait itself.
	stopping := make(chan struct{})
	waited := make(chan struct{})
	go func() {
		err := cmd.Wait()
		// Release stop() before the callback, not after: whatever onDeath
		// decides to do, stop() is done waiting the moment the process is
		// reaped.
		close(waited)
		select {
		case <-stopping: // stop() killed it; expected.
		default:
			// A clean exit is still a death: nothing else stops kubectl. Wait
			// returns nil then, and %w of a nil error would print garbage.
			if err == nil {
				err = errors.New("exit status 0")
			}
			onDeath(fmt.Errorf("kubectl port-forward exited (%w): %s",
				err, strings.TrimSpace(stderr.String())))
		}
	}()

	stop := func() {
		close(stopping)
		_ = cmd.Process.Kill()
		<-waited
	}

	return port, stop, nil
}

// forwardedPort matches kubectl's "Forwarding from 127.0.0.1:54321 -> 8443".
var forwardedPort = regexp.MustCompile(`^Forwarding from 127\.0\.0\.1:(\d+) ->`)

func readForwardedPort(stdout io.Reader) (int, error) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		m := forwardedPort.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}

		return strconv.Atoi(m[1])
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("failed to read kubectl port-forward output: %w", err)
	}

	return 0, errors.New("kubectl port-forward exited before it announced a local port")
}
