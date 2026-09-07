// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"fmt"
	"sort"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// Sample is one series of a Prometheus exposition. A histogram contributes
// one sample per bucket (family name plus _bucket, with le), plus _count and
// _sum; a summary contributes one sample per objective (the family name, with
// quantile), plus _count and _sum. Assertions address them the way PromQL
// does.
type Sample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// ParseMetrics parses a Prometheus text exposition with the reference
// parser. Any malformed line is an error: the suite asserts on what the proxy
// serves, and a line it cannot read is a finding, not noise.
func ParseMetrics(text string) ([]Sample, error) {
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(text))
	if err != nil {
		return nil, fmt.Errorf("parsing exposition: %w", err)
	}
	names := make([]string, 0, len(families))
	for name := range families {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []Sample
	for _, name := range names {
		for _, m := range families[name].GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			switch {
			case m.Counter != nil:
				out = append(out, Sample{Name: name, Labels: labels, Value: m.Counter.GetValue()})
			case m.Gauge != nil:
				out = append(out, Sample{Name: name, Labels: labels, Value: m.Gauge.GetValue()})
			case m.Untyped != nil:
				out = append(out, Sample{Name: name, Labels: labels, Value: m.Untyped.GetValue()})
			case m.Histogram != nil:
				out = append(out, histogramSamples(name, labels, m.Histogram)...)
			case m.Summary != nil:
				out = append(out, summarySamples(name, labels, m.Summary)...)
			}
		}
	}
	return out, nil
}

func histogramSamples(name string, labels map[string]string, h *dto.Histogram) []Sample {
	var out []Sample
	for _, b := range h.GetBucket() {
		l := make(map[string]string, len(labels)+1)
		for k, v := range labels {
			l[k] = v
		}
		l["le"] = fmt.Sprint(b.GetUpperBound())
		out = append(out, Sample{Name: name + "_bucket", Labels: l, Value: float64(b.GetCumulativeCount())})
	}
	out = append(out,
		Sample{Name: name + "_count", Labels: labels, Value: float64(h.GetSampleCount())},
		Sample{Name: name + "_sum", Labels: labels, Value: h.GetSampleSum()},
	)
	return out
}

// summarySamples renders a summary the way PromQL addresses it: the family
// name with a quantile label per objective, plus _count and _sum. The Go
// collector exposes go_gc_duration_seconds this way, so a scrape of any Go
// binary contains one.
func summarySamples(name string, labels map[string]string, s *dto.Summary) []Sample {
	var out []Sample
	for _, q := range s.GetQuantile() {
		l := make(map[string]string, len(labels)+1)
		for k, v := range labels {
			l[k] = v
		}
		l["quantile"] = fmt.Sprint(q.GetQuantile())
		out = append(out, Sample{Name: name, Labels: l, Value: q.GetValue()})
	}
	out = append(out,
		Sample{Name: name + "_count", Labels: labels, Value: float64(s.GetSampleCount())},
		Sample{Name: name + "_sum", Labels: labels, Value: s.GetSampleSum()},
	)
	return out
}

// SampleValue returns the value of the first sample of family name that
// carries every given label with that value. An expected label the sample
// lacks is a mismatch, even when the expected value is empty.
func SampleValue(samples []Sample, name string, labels map[string]string) (float64, bool) {
	for _, s := range samples {
		if s.Name != name {
			continue
		}
		match := true
		for k, v := range labels {
			actual, present := s.Labels[k]
			if !present || actual != v {
				match = false
				break
			}
		}
		if match {
			return s.Value, true
		}
	}
	return 0, false
}

// LabelValuesOf returns every distinct value of label across family name.
func LabelValuesOf(samples []Sample, name, label string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range samples {
		if s.Name != name {
			continue
		}
		if v, ok := s.Labels[label]; ok && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
