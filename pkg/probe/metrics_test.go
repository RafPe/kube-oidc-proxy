// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"log/slog"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
)

const (
	metricIssuerInitialized = "kube_oidc_proxy_oidc_issuer_initialized"
	metricReady             = "kube_oidc_proxy_ready"
)

func newMetricsRecorder(t *testing.T) *metrics.Recorder {
	t.Helper()
	r, err := metrics.New(metrics.BuildInfo{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestProbePublishesIssuerAndReadyGauges(t *testing.T) {
	issuerA := "https://a.example.com/realm"
	issuerB := "https://b.example.com"
	rec := newMetricsRecorder(t)

	s := NewServer(Config{
		Issuers:       issuersFor(issuerA, issuerB),
		Authenticator: &fakeAuthenticator{notInit: map[string]bool{issuerB: true}},
		Metrics:       rec,
	}, slog.New(slog.DiscardHandler))
	g := rec.Gatherer()

	// Every configured issuer has a series from construction, at 0.
	for _, name := range []string{"a.example.com", "b.example.com"} {
		if v, ok := metricstest.Value(t, g, metricIssuerInitialized, map[string]string{"issuer_name": name}); !ok || v != 0 {
			t.Fatalf("issuer %s before any check = %v (present=%v), want 0", name, v, ok)
		}
	}
	if v, _ := metricstest.Value(t, g, metricReady, nil); v != 0 {
		t.Fatalf("ready before serving = %v, want 0", v)
	}

	s.SetServing()
	if err := s.check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v, _ := metricstest.Value(t, g, metricIssuerInitialized, map[string]string{"issuer_name": "a.example.com"}); v != 1 {
		t.Fatalf("issuer a after check = %v, want 1", v)
	}
	if v, _ := metricstest.Value(t, g, metricIssuerInitialized, map[string]string{"issuer_name": "b.example.com"}); v != 0 {
		t.Fatalf("issuer b (pending) after check = %v, want 0", v)
	}
	if v, _ := metricstest.Value(t, g, metricReady, nil); v != 1 {
		t.Fatalf("ready after latch = %v, want 1", v)
	}
	// The label is the host, never the raw URL.
	for _, v := range metricstest.LabelValues(t, g, metricIssuerInitialized, "issuer_name") {
		if v == issuerA || v == issuerB {
			t.Fatalf("issuer_name leaked a full URL: %q", v)
		}
	}
}

// TestProbeNamesIssuersByTheirConfiguredName pins that the probe reports each
// issuer under the name authn.Build resolved, not under a name it derives
// from the issuer URL.
func TestProbeNamesIssuersByTheirConfiguredName(t *testing.T) {
	issuerA := "https://shared.example.com/a"
	issuerB := "https://shared.example.com/b"
	rec := newMetricsRecorder(t)
	root, cap := logtest.New(t, 0)

	s := NewServer(Config{
		Issuers: []authn.Issuer{
			{Name: "corp-a", URL: issuerA},
			{Name: "corp-b", URL: issuerB},
		},
		Authenticator: &fakeAuthenticator{notInit: map[string]bool{issuerB: true}},
		Metrics:       rec,
	}, root)
	g := rec.Gatherer()

	s.SetServing()
	if err := s.check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v, ok := metricstest.Value(t, g, metricIssuerInitialized, map[string]string{"issuer_name": "corp-a"}); !ok || v != 1 {
		t.Fatalf("issuer corp-a after check = %v (present=%v), want 1", v, ok)
	}
	if v, ok := metricstest.Value(t, g, metricIssuerInitialized, map[string]string{"issuer_name": "corp-b"}); !ok || v != 0 {
		t.Fatalf("issuer corp-b after check = %v (present=%v), want 0", v, ok)
	}
	if got := cap.Only(t, logging.EventOIDCIssuerInitialized).String("issuer_name"); got != "corp-a" {
		t.Fatalf("initialized record issuer_name = %q, want corp-a", got)
	}
	if got := cap.Only(t, logging.EventOIDCIssuerPending).String("issuer_name"); got != "corp-b" {
		t.Fatalf("pending record issuer_name = %q, want corp-b", got)
	}
}
