// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"strings"
	"testing"
)

// TestChartMetricsSurfaceMatchesTheBinary is the guard between the chart and
// the code for metrics: the flag the chart renders must be the flag the
// binary accepts, and its port must be the named container port and the
// Service port a ServiceMonitor references.
func TestChartMetricsSurfaceMatchesTheBinary(t *testing.T) {
	s, err := ChartMetricsSurfaceFor(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.BindAddressArg, "--metrics-bind-address=") {
		t.Fatalf("BindAddressArg = %q", s.BindAddressArg)
	}
	if !strings.HasSuffix(s.BindAddressArg, ":9090") || s.ContainerPort != 9090 || s.ServicePort != 9090 {
		t.Fatalf("flag %q, container port %d, Service port %d must agree on 9090", s.BindAddressArg, s.ContainerPort, s.ServicePort)
	}
	if s.PortName != "metrics" {
		t.Fatalf("PortName = %q, want metrics", s.PortName)
	}
	if s.ServiceName != "e2e-kube-oidc-proxy-metrics" {
		t.Fatalf("ServiceName = %q", s.ServiceName)
	}
}
