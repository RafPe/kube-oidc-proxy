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
)

// discard is the root logger for a shutdown test that does not assert on
// records.
var discard = slog.New(slog.DiscardHandler)

// fakeStep stands in for any of the collaborators shutdown tears down. Each
// call appends name to order and returns err where the method returns one.
type fakeStep struct {
	name  string
	order *[]string
	err   error
}

func (f fakeStep) Wait() error { *f.order = append(*f.order, f.name); return f.err }
func (f fakeStep) Shutdown()   { *f.order = append(*f.order, f.name) }
func (f fakeStep) Stop() error { *f.order = append(*f.order, f.name); return f.err }

// funcFlusher adapts a function to the flusher shutdown calls.
type funcFlusher func()

func (f funcFlusher) Shutdown() { f() }

// TestShutdownStopsTheMetricsListenerLast pins the shutdown order: the
// metrics listener stops last, so a scrape landing anywhere in the drain
// window still reaches it.
func TestShutdownStopsTheMetricsListenerLast(t *testing.T) {
	var order []string
	err := shutdown(discard,
		fakeStep{name: "wait readiness", order: &order},
		fakeStep{name: "flush audit", order: &order},
		fakeStep{name: "stop metrics", order: &order})
	if err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	want := []string{"wait readiness", "flush audit", "stop metrics"}
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

	readinessErr := errors.New("readiness drain overran")
	metricsErr := errors.New("metrics drain overran")

	var order []string
	err := shutdown(root,
		fakeStep{name: "readiness", order: &order, err: readinessErr},
		fakeStep{name: "audit", order: &order},
		fakeStep{name: "metrics", order: &order, err: metricsErr})
	if len(order) != 3 {
		t.Fatalf("ran %v, want all three steps", order)
	}
	for _, want := range []error{readinessErr, metricsErr} {
		if !errors.Is(err, want) {
			t.Fatalf("shutdown error = %v, want it to carry %v", err, want)
		}
	}
	logs.Only(t, logging.EventProxyShutdownCompleted)
}

// TestShutdownKeepsTheMetricsEndpointUpForTheFlush is the property the order
// exists for: a scrape that lands while the audit flush is running still
// reaches the listener and reads the state recorded before shutdown began.
func TestShutdownKeepsTheMetricsEndpointUpForTheFlush(t *testing.T) {
	rec, err := metrics.New(metrics.BuildInfo{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	srv := metrics.NewServer(metrics.ServerConfig{Addr: "127.0.0.1:0", Recorder: rec}, discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	rec.SetReady(true)

	var body string
	var scrapeErr error
	flush := funcFlusher(func() {
		resp, err := http.Get("http://" + srv.Addr() + "/metrics")
		if err != nil {
			scrapeErr = fmt.Errorf("scraping during the drain window: %w", err)
			return
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		scrapeErr = err
		body = string(raw)
	})

	var order []string
	if err := shutdown(discard, fakeStep{name: "readiness", order: &order}, flush,
		&metricsListener{server: srv, cancel: cancel}); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	if scrapeErr != nil {
		t.Fatal(scrapeErr)
	}
	if !strings.Contains(body, "kube_oidc_proxy_ready 1") {
		t.Fatalf("the metrics endpoint was not scrapeable during the drain window:\n%s", body)
	}
}

// TestShutdownWithoutMetricsListener pins the disabled-metrics path: a nil
// listener stops as a no-op, and the other steps still run.
func TestShutdownWithoutMetricsListener(t *testing.T) {
	var order []string
	var disabled *metricsListener
	if err := shutdown(discard, fakeStep{name: "readiness", order: &order},
		fakeStep{name: "audit", order: &order}, disabled); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if len(order) != 2 {
		t.Fatalf("ran %v, want the readiness wait and the audit flush", order)
	}
}
