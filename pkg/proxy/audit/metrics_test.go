// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"k8s.io/apiserver/pkg/server"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
)

const metricAuditFailures = "kube_oidc_proxy_audit_backend_failures_total"

func newAuditWithBackend(t *testing.T, b *fakeBackend, rec *metrics.Recorder) *Audit {
	t.Helper()
	a, err := New(Config{ExternalAddress: "0.0.0.0:1234", SecureServing: new(server.SecureServingInfo)}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	a.serverConfig.AuditBackend = b
	a.metrics = rec
	return a
}

func TestAuditRunFailureIsCounted(t *testing.T) {
	rec, _ := metrics.New(metrics.BuildInfo{Version: "test"})
	a := newAuditWithBackend(t, &fakeBackend{runErr: errors.New("cannot start")}, rec)
	if err := a.Start(context.Background()); err == nil {
		t.Fatal("Run should fail")
	}
	if v, _ := metricstest.Value(t, rec.Gatherer(), metricAuditFailures, map[string]string{"operation": "run"}); v != 1 {
		t.Fatalf("run failures = %v, want 1", v)
	}
}

func TestAuditCleanShutdownCountsNothing(t *testing.T) {
	rec, _ := metrics.New(metrics.BuildInfo{Version: "test"})
	a := newAuditWithBackend(t, &fakeBackend{}, rec)
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.Shutdown()
	if n := metricstest.SeriesCount(t, rec.Gatherer(), metricAuditFailures); n != 0 {
		t.Fatalf("failure series after a clean run = %d, want 0", n)
	}
}
