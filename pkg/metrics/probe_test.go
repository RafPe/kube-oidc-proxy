// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
)

func TestIssuerAndReadyGauges(t *testing.T) {
	r := newTestRecorder(t)
	r.SetIssuerInitialized("idp.example.com", false)
	r.SetIssuerInitialized("other.example.com", false)
	r.SetIssuerInitialized("idp.example.com", true)
	r.SetReady(true)
	g := r.Gatherer()
	if v, _ := metricstest.Value(t, g, nameIssuerInitialized, map[string]string{"issuer_name": "idp.example.com"}); v != 1 {
		t.Fatalf("issuer idp = %v, want 1", v)
	}
	if v, _ := metricstest.Value(t, g, nameIssuerInitialized, map[string]string{"issuer_name": "other.example.com"}); v != 0 {
		t.Fatalf("issuer other = %v, want 0", v)
	}
	if v, _ := metricstest.Value(t, g, nameReady, nil); v != 1 {
		t.Fatalf("ready = %v, want 1", v)
	}
	var nilr *Recorder
	nilr.SetIssuerInitialized("x", true)
	nilr.SetReady(true)
}
