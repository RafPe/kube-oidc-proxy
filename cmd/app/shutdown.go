// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
)

// drain runs the shutdown sequence once the proxy has stopped serving, and
// joins every failure it collects, so a listener that never released its port
// and a hook that could not flush both reach the exit status. No step is
// skipped because an earlier one failed.
//
// The order matters. The readiness listener began stopping when the stop
// signal cancelled its context, so nothing new is admitted; drain waits for it
// first. The audit flush runs next; it reports through the recorder -- the
// audit backend increments the operation="shutdown" counter -- so the metrics
// listener stops last, and a scrape landing in the drain window can still read
// what it recorded.
//
// stopMetrics stops the metrics listener and waits for it; with the listener
// disabled it is noStep, so every step is always called.
func drain(waitProbe, flushAudit, stopMetrics func() error) error {
	probeErr := waitProbe()
	flushErr := flushAudit()
	metricsErr := stopMetrics()

	return errors.Join(probeErr, flushErr, metricsErr)
}

// auditHook names the audit flush in the pre-shutdown hook records.
const auditHook = "AuditBackend"

// flushAuditStep returns the drain step that flushes the audit backend. It
// reports the flush as a hook record, so a shutdown that takes too long names
// the step responsible, and a failed flush -- events for requests already
// served were dropped -- is never silent.
func flushAuditStep(auditor *audit.Audit, root *slog.Logger) func() error {
	return func() error {
		logger := logging.ForComponent(root, logging.ComponentShutdown)
		ctx := context.Background()

		start := time.Now()
		err := auditor.Shutdown()
		elapsed := time.Since(start)

		if err != nil {
			logging.Emit(ctx, logger, logging.EventProxyHookFailed,
				slog.String("hook", auditHook),
				slog.Int64("duration_ms", elapsed.Milliseconds()),
				logging.ErrAttr(err))
			return fmt.Errorf("pre-shutdown hook %q failed: %w", auditHook, err)
		}

		logging.Emit(ctx, logger, logging.EventProxyHookCompleted,
			slog.String("hook", auditHook),
			slog.Int64("duration_ms", elapsed.Milliseconds()))
		return nil
	}
}

// noStep is the drain step for a listener that was never started.
func noStep() error { return nil }

// shutdown drains the listeners and flushes the audit backend, then reports
// that the teardown finished. The record is emitted whether or not a step
// failed: the milestone is that the teardown finished, and the failing step
// has already named itself.
func shutdown(root *slog.Logger, waitProbe, flushAudit, stopMetrics func() error) error {
	shutdownSince := time.Now()
	err := drain(waitProbe, flushAudit, stopMetrics)

	logging.Emit(context.Background(), logging.ForComponent(root, logging.ComponentShutdown),
		logging.EventProxyShutdownCompleted,
		slog.Int64("duration_ms", time.Since(shutdownSince).Milliseconds()))
	return err
}
