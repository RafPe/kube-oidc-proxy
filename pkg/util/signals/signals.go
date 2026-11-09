// Copyright Jetstack Ltd. See LICENSE for details.

// Package signals installs OS signal handling for graceful shutdown. It maps
// SIGINT/SIGTERM onto a context that is cancelled to begin an orderly
// teardown.
package signals

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// forcedSignalCount is the repeat signal, counted after the first, that stops
// waiting for the graceful teardown and exits: the repeats before it are
// absorbed.
const forcedSignalCount = 3

// signalName renders a signal as the name an operator typed or a supervisor
// sent. sig.String() gives the description ("terminated", "interrupt"), which
// is not the value the log contract carries.
func signalName(sig os.Signal) string {
	switch sig {
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGINT:
		return "SIGINT"
	default:
		return logging.Bound(sig.String(), logging.MaxIdentity)
	}
}

// NotifyContext installs a SIGINT/SIGTERM handler and returns a context
// derived from parent that is cancelled on the first such signal, requesting a
// graceful shutdown. The next two signals are absorbed while the teardown
// runs; the third repeat forces an immediate os.Exit(1). stop unregisters the
// handler and releases the context. NotifyContext is intended to be called
// once during process startup.
//
// logger is the shutdown-component logger the handler reports through.
func NotifyContext(parent context.Context, logger *slog.Logger) (ctx context.Context, stop context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)

	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	handle(logger, ch, cancel, func() { os.Exit(1) })

	return ctx, func() {
		signal.Stop(ch)
		cancel()
	}
}

// handle is NotifyContext's behaviour with the process-wide dependencies passed
// in: the signal source, the shutdown request and the forced exit.
// NotifyContext supplies the real ones; a test supplies a channel it writes to
// and an exit it can observe, so the whole sequence is exercised without
// signalling the test process or killing it.
//
// The first signal is reported once rather than on every repeat: the shutdown
// has already started, and restating it says nothing new. The forced exit is
// the same event with forced=true. Once stop has unregistered the handler, ch
// receives nothing more and the goroutine simply stays parked.
func handle(logger *slog.Logger, ch <-chan os.Signal, shutdown, exit func()) {
	go func() {
		ctx := context.Background()
		sig := <-ch

		shutdown()

		logging.Emit(ctx, logger, logging.EventProxyShutdownStarted,
			slog.String("signal", signalName(sig)))

		for i := 0; i < forcedSignalCount; i++ {
			sig = <-ch
		}

		logging.Emit(ctx, logger, logging.EventProxyShutdownStarted,
			slog.String("signal", signalName(sig)),
			slog.Bool("forced", true))

		exit()
	}()
}
