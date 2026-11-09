// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
)

// auditHook names the audit flush in the pre-shutdown hook records.
const auditHook = "AuditBackend"

// flushAuditStep returns the shutdown step that flushes the audit backend. It
// reports the flush as a hook record, so a shutdown that takes too long names
// the step responsible. The step cannot fail: the upstream audit backends have
// no way to report a lost flush through Shutdown (see audit.Audit.Shutdown).
func flushAuditStep(auditor *audit.Audit, root *slog.Logger) func() error {
	return func() error {
		start := time.Now()
		auditor.Shutdown()

		logging.Emit(context.Background(), logging.ForComponent(root, logging.ComponentShutdown),
			logging.EventProxyHookCompleted,
			slog.String("hook", auditHook),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()))
		return nil
	}
}

// noStep is the shutdown step for a listener that was never started.
func noStep() error { return nil }

// shutdown runs the teardown once the proxy has stopped serving, then reports
// that it finished. Every step runs and every failure is joined into the
// result, so a listener that never released its port and a hook that could
// not flush both reach the exit status; no step is skipped because an earlier
// one failed. The completion record is emitted whether or not a step failed:
// the milestone is that the teardown finished, and the failing step has
// already named itself.
//
// The order matters. The readiness listener began stopping when the stop
// signal cancelled its context, so nothing new is admitted; shutdown waits for
// it first. The audit flush runs next. The metrics listener stops last, so a
// scrape landing anywhere in the drain window still reaches it and reads the
// final state of everything recorded before it.
//
// stopMetrics stops the metrics listener and waits for it; with the listener
// disabled it is noStep, so every step is always called.
func shutdown(root *slog.Logger, waitProbe, flushAudit, stopMetrics func() error) error {
	shutdownSince := time.Now()

	probeErr := waitProbe()
	flushErr := flushAudit()
	metricsErr := stopMetrics()

	logging.Emit(context.Background(), logging.ForComponent(root, logging.ComponentShutdown),
		logging.EventProxyShutdownCompleted,
		slog.Int64("duration_ms", time.Since(shutdownSince).Milliseconds()))
	return errors.Join(probeErr, flushErr, metricsErr)
}
