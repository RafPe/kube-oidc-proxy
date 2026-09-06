// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"errors"
	"log/slog"
	"testing"

	"k8s.io/apiserver/pkg/server"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
)

const metricAuditFailures = "kube_oidc_proxy_audit_backend_failures_total"

func newAuditWithBackend(t *testing.T, b *fakeBackend, rec *metrics.Recorder) *Audit {
	t.Helper()
	a, err := New(new(options.AuditOptions), "0.0.0.0:1234", new(server.SecureServingInfo), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	a.serverConfig.AuditBackend = b
	return a.WithMetrics(rec)
}

func TestAuditRunFailureIsCounted(t *testing.T) {
	rec, _ := metrics.New(metrics.BuildInfo{Version: "test"})
	a := newAuditWithBackend(t, &fakeBackend{runErr: errors.New("cannot start")}, rec)
	if err := a.Run(make(chan struct{})); err == nil {
		t.Fatal("Run should fail")
	}
	if v, _ := metricstest.Value(t, rec.Gatherer(), metricAuditFailures, map[string]string{"operation": "run"}); v != 1 {
		t.Fatalf("run failures = %v, want 1", v)
	}
}

func TestAuditShutdownFailureIsCounted(t *testing.T) {
	rec, _ := metrics.New(metrics.BuildInfo{Version: "test"})
	a := newAuditWithBackend(t, &fakeBackend{shutdownErr: errors.New("dropped events")}, rec)
	if err := a.Shutdown(); err == nil {
		t.Fatal("Shutdown should fail")
	}
	if v, _ := metricstest.Value(t, rec.Gatherer(), metricAuditFailures, map[string]string{"operation": "shutdown"}); v != 1 {
		t.Fatalf("shutdown failures = %v, want 1", v)
	}
}

func TestAuditCleanShutdownCountsNothing(t *testing.T) {
	rec, _ := metrics.New(metrics.BuildInfo{Version: "test"})
	a := newAuditWithBackend(t, &fakeBackend{}, rec)
	if err := a.Run(make(chan struct{})); err != nil {
		t.Fatal(err)
	}
	if err := a.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if n := metricstest.SeriesCount(t, rec.Gatherer(), metricAuditFailures); n != 0 {
		t.Fatalf("failure series after a clean run = %d, want 0", n)
	}
}
