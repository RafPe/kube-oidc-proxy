// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
)

func TestAuditBackendFailure(t *testing.T) {
	r := newTestRecorder(t)
	r.AuditBackendFailure(AuditRun)
	r.AuditBackendFailure(AuditShutdown)
	r.AuditBackendFailure(AuditShutdown)
	r.AuditBackendFailure(AuditOperation("x"))
	g := r.Gatherer()
	if v, _ := metricstest.Value(t, g, nameAuditBackendFailures, map[string]string{"operation": "run"}); v != 1 {
		t.Fatalf("run failures = %v", v)
	}
	if v, _ := metricstest.Value(t, g, nameAuditBackendFailures, map[string]string{"operation": "shutdown"}); v != 2 {
		t.Fatalf("shutdown failures = %v", v)
	}
	if v, _ := metricstest.Value(t, g, nameAuditBackendFailures, map[string]string{"operation": "other"}); v != 1 {
		t.Fatalf("unknown operation not projected: %v", v)
	}
	var nilr *Recorder
	nilr.AuditBackendFailure(AuditRun)
}
