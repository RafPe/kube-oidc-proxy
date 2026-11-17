// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// The collaborators shutdown tears down, by what it needs from each.
type (
	// drainingListener is a listener that began draining when its context
	// was cancelled; Wait returns once the drain finished. The readiness
	// listener is one.
	drainingListener interface{ Wait() error }

	// shutdowner flushes buffered events on Shutdown. Flushing cannot fail:
	// the upstream audit backends have no way to report a lost flush through
	// Shutdown (see audit.Audit.Shutdown), which reports its own record. The
	// auditor is one.
	shutdowner interface{ Shutdown() }

	// stoppableListener is a listener only shutdown stops; Stop returns once
	// its drain finished. The metrics listener is one.
	stoppableListener interface{ Stop() error }
)

// shutdown runs the teardown once the proxy has stopped serving, then reports
// that it finished. Every step runs and every failure is joined into the
// result, so a listener that never released its port reaches the exit status
// and no step is skipped because an earlier one failed. The completion record
// is emitted whether or not a step failed: the milestone is that the teardown
// finished, and the failing step has already named itself.
//
// The order matters. The readiness listener began stopping when the stop
// signal cancelled its context, so nothing new is admitted; shutdown waits for
// it first. The audit flush runs next. The metrics listener stops last, so a
// scrape landing anywhere in the drain window still reaches it and reads the
// final state of everything recorded before it.
func shutdown(root *slog.Logger, readiness drainingListener, auditor shutdowner, metrics stoppableListener) error {
	shutdownSince := time.Now()

	readinessErr := readiness.Wait()
	auditor.Shutdown()
	metricsErr := metrics.Stop()

	logging.Emit(context.Background(), logging.ForComponent(root, logging.ComponentShutdown),
		logging.EventProxyShutdownCompleted,
		slog.Int64("duration_ms", time.Since(shutdownSince).Milliseconds()))
	return errors.Join(readinessErr, metricsErr)
}
