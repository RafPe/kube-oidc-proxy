// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
)

// discard is the root logger for a shutdown test that does not assert on
// records.
var discard = slog.New(slog.DiscardHandler)

// TestShutdownStopsTheMetricsListenerAfterTheHooks pins the shutdown order:
// the metrics listener stops last, so a scrape landing anywhere in the drain
// window still reaches it.
func TestShutdownStopsTheMetricsListenerAfterTheHooks(t *testing.T) {
	var order []string
	note := func(step string) func() error {
		return func() error { order = append(order, step); return nil }
	}

	err := shutdown(discard, note("wait probe"), note("flush audit"), note("stop metrics"))
	if err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	want := []string{"wait probe", "flush audit", "stop metrics"}
	if !slices.Equal(order, want) {
		t.Fatalf("shutdown order = %v, want %v", order, want)
	}
}

// TestShutdownJoinsEveryFailure pins that no step is skipped because an
// earlier one failed, that every failure reaches the exit status, and that
// the teardown still reports it finished.
func TestShutdownJoinsEveryFailure(t *testing.T) {
	root, logs := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, logs)

	probeErr := errors.New("probe drain overran")
	hooksErr := errors.New("audit flush failed")
	metricsErr := errors.New("metrics drain overran")

	ran := 0
	err := shutdown(root,
		func() error { ran++; return probeErr },
		func() error { ran++; return hooksErr },
		func() error { ran++; return metricsErr },
	)
	if ran != 3 {
		t.Fatalf("ran %d steps, want 3", ran)
	}
	for _, want := range []error{probeErr, hooksErr, metricsErr} {
		if !errors.Is(err, want) {
			t.Fatalf("shutdown error = %v, want it to carry %v", err, want)
		}
	}
	logs.Only(t, logging.EventProxyShutdownCompleted)
}

// TestShutdownKeepsTheMetricsEndpointUpForTheHooks is the property the order
// exists for: a scrape that lands while the hooks are running still reaches
// the listener and reads the state recorded before shutdown began.
func TestShutdownKeepsTheMetricsEndpointUpForTheHooks(t *testing.T) {
	rec, err := metrics.New(metrics.BuildInfo{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := metrics.NewServer(metrics.ServerConfig{Addr: "127.0.0.1:0", Recorder: rec}, discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancelMetrics := context.WithCancel(context.Background())
	defer cancelMetrics()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	addr := srv.Addr()
	rec.SetReady(true)

	var body string
	hooks := func() error {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err != nil {
			return fmt.Errorf("scraping during the drain window: %w", err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		body = string(raw)
		return nil
	}

	if err := shutdown(discard, func() error { return nil }, hooks,
		func() error { cancelMetrics(); return srv.Wait() }); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	if !strings.Contains(body, "kube_oidc_proxy_ready 1") {
		t.Fatalf("the metrics endpoint was not scrapeable during the drain window:\n%s", body)
	}
}

// TestShutdownWithoutMetricsListener pins the disabled-metrics path: there is no
// listener to stop, and the other steps still run.
func TestShutdownWithoutMetricsListener(t *testing.T) {
	ran := 0
	step := func() error { ran++; return nil }
	if err := shutdown(discard, step, step, noStep); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if ran != 2 {
		t.Fatalf("ran %d steps, want 2", ran)
	}
}

// TestFlushAuditStepReportsAHookRecord pins the pre-shutdown record: one
// proxy.hook.completed naming the audit backend step, under the shutdown
// component, with its duration.
func TestFlushAuditStepReportsAHookRecord(t *testing.T) {
	root, logs := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, logs)

	auditor, err := audit.New(audit.Config{ExternalAddress: "0.0.0.0:1234"},
		logging.ForComponent(root, logging.ComponentAudit))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}

	if err := flushAuditStep(auditor, root)(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	rec := logs.Only(t, logging.EventProxyHookCompleted)
	if got := rec.String("hook"); got != auditHook {
		t.Errorf("hook = %q, want %q", got, auditHook)
	}
	if got := rec.String("component"); got != string(logging.ComponentShutdown) {
		t.Errorf("component = %q, want shutdown", got)
	}
	if _, ok := rec.Int("duration_ms"); !ok {
		t.Error("duration_ms missing")
	}
}
