// Copyright Jetstack Ltd. See LICENSE for details.

// Package signals installs OS signal handling for graceful shutdown. It maps
// SIGINT/SIGTERM onto a stop channel that callers can wait on to begin an
// orderly teardown.
package signals

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// forcedSignalCount is how many further signals are absorbed after the first
// before the process stops waiting for a graceful teardown and exits.
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

// Handler installs a SIGINT/SIGTERM handler and returns a stop channel that is
// closed on the first such signal, requesting a graceful shutdown. Each
// subsequent signal (up to three) is absorbed while the teardown runs; the
// next one after that forces an immediate os.Exit(1). Handler is intended to be
// called once during process startup.
//
// logger is the shutdown-component logger the handler reports through.
func Handler(logger *slog.Logger) chan struct{} {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	return handle(logger, ch, func() { os.Exit(1) })
}

// handle is Handler's behaviour with the two process-wide dependencies passed
// in: the signal source and the forced exit. Handler supplies the real ones; a
// test supplies a channel it writes to and an exit it can observe, so the whole
// sequence is exercised without signalling the test process or killing it.
//
// The first signal is reported once rather than on every repeat: the shutdown
// has already started, and restating it says nothing new. The forced exit is
// the same event with forced=true.
func handle(logger *slog.Logger, ch <-chan os.Signal, exit func()) chan struct{} {
	stopCh := make(chan struct{})

	go func() {
		ctx := context.Background()
		sig := <-ch

		close(stopCh)

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

	return stopCh
}
