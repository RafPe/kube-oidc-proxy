// Copyright Jetstack Ltd. See LICENSE for details.
package metricstest

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestValueRequiresLabelPresence(t *testing.T) {
	reg := prometheus.NewRegistry()
	vec := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "t_total", Help: "t"}, []string{"reason"})
	reg.MustRegister(vec)
	vec.WithLabelValues("").Inc()

	if v, ok := Value(t, reg, "t_total", map[string]string{"reason": ""}); !ok || v != 1 {
		t.Fatalf("empty reason present: value %v ok %v, want 1 true", v, ok)
	}
	if _, ok := Value(t, reg, "t_total", map[string]string{"missing": ""}); ok {
		t.Fatal("an absent label matched an empty wanted value")
	}
	if n := SeriesCount(t, reg, "t_total"); n != 1 {
		t.Fatalf("SeriesCount = %d, want 1", n)
	}
	if got := LabelValues(t, reg, "t_total", "reason"); len(got) != 1 || got[0] != "" {
		t.Fatalf("LabelValues = %q, want [\"\"]", got)
	}
}
