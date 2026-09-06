// Copyright Jetstack Ltd. See LICENSE for details.

// Package metricstest reads samples back out of a Gatherer so tests in any
// package can assert on what the recorder exports without reaching into its
// collectors.
package metricstest

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Value returns the value of the sample of family name whose labels match
// labels exactly (every given label must be present with that value; labels
// not given are ignored). For a histogram it returns the sample count. The
// bool reports whether such a sample exists.
func Value(t testing.TB, g prometheus.Gatherer, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	for _, m := range samples(t, g, name) {
		if !hasLabels(m, labels) {
			continue
		}
		switch {
		case m.Counter != nil:
			return m.Counter.GetValue(), true
		case m.Gauge != nil:
			return m.Gauge.GetValue(), true
		case m.Histogram != nil:
			return float64(m.Histogram.GetSampleCount()), true
		}
	}
	return 0, false
}

// SeriesCount returns how many samples family name currently has.
func SeriesCount(t testing.TB, g prometheus.Gatherer, name string) int {
	t.Helper()
	return len(samples(t, g, name))
}

// LabelValues returns every distinct value of label across family name.
func LabelValues(t testing.TB, g prometheus.Gatherer, name, label string) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	for _, m := range samples(t, g, name) {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == label && !seen[lp.GetValue()] {
				seen[lp.GetValue()] = true
				out = append(out, lp.GetValue())
			}
		}
	}
	return out
}

func samples(t testing.TB, g prometheus.Gatherer, name string) []*dto.Metric {
	t.Helper()
	families, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f.GetMetric()
		}
	}
	return nil
}

func hasLabels(m *dto.Metric, want map[string]string) bool {
	got := map[string]string{}
	for _, lp := range m.GetLabel() {
		got[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}
