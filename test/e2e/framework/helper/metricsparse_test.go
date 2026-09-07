// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import "testing"

func TestParseMetrics(t *testing.T) {
	text := `# HELP kube_oidc_proxy_ready [STABLE] 1 once ready.
# TYPE kube_oidc_proxy_ready gauge
kube_oidc_proxy_ready 1
kube_oidc_proxy_requests_total{k8s_verb="list",scope="namespace",code="200",termination="normal"} 3
# TYPE kube_oidc_proxy_request_duration_seconds histogram
kube_oidc_proxy_request_duration_seconds_bucket{k8s_verb="get",scope="resource",le="+Inf"} 2
go_goroutines 12
`
	samples, err := ParseMetrics(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 6 {
		// ready, requests_total, the bucket plus the histogram's _count and
		// _sum, and go_goroutines.
		t.Fatalf("parsed %d samples, want 6: %+v", len(samples), samples)
	}
	v, ok := SampleValue(samples, "kube_oidc_proxy_requests_total", map[string]string{"k8s_verb": "list", "code": "200"})
	if !ok || v != 3 {
		t.Fatalf("requests_total = %v (present=%v), want 3", v, ok)
	}
	if v, ok := SampleValue(samples, "kube_oidc_proxy_ready", nil); !ok || v != 1 {
		t.Fatalf("ready = %v (present=%v)", v, ok)
	}
	if _, ok := SampleValue(samples, "missing", nil); ok {
		t.Fatal("missing family reported present")
	}
	// A required label that is absent does not match an expected empty value.
	if _, ok := SampleValue(samples, "go_goroutines", map[string]string{"k8s_verb": ""}); ok {
		t.Fatal("absent label matched an empty expected value")
	}
}

func TestParseMetricsRejectsMalformedInput(t *testing.T) {
	for name, text := range map[string]string{
		"non-numeric value":  "kube_oidc_proxy_ready not-a-number\n",
		"unterminated label": "kube_oidc_proxy_requests_total{k8s_verb=\"list\" 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMetrics(text); err == nil {
				t.Fatalf("ParseMetrics(%q) = nil error, want a parse error", text)
			}
		})
	}
}

// TestParseMetricsReadsSummaries pins that summary families survive the
// parse. The Go collector exposes go_gc_duration_seconds as a summary, so a
// parser that drops the type silently loses every sample of it -- and with
// it any assertion sweeping over "every label the endpoint serves".
func TestParseMetricsReadsSummaries(t *testing.T) {
	text := `# HELP go_gc_duration_seconds A summary of the wall-time pause.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 1e-05
go_gc_duration_seconds{quantile="0.5"} 2e-05
go_gc_duration_seconds{quantile="1"} 3e-05
go_gc_duration_seconds_sum 0.0001
go_gc_duration_seconds_count 4
`
	samples, err := ParseMetrics(text)
	if err != nil {
		t.Fatal(err)
	}
	// Three quantiles plus _count and _sum.
	if len(samples) != 5 {
		t.Fatalf("parsed %d samples, want 5: %+v", len(samples), samples)
	}
	v, ok := SampleValue(samples, "go_gc_duration_seconds", map[string]string{"quantile": "0.5"})
	if !ok || v != 2e-05 {
		t.Fatalf("quantile 0.5 = %v (present=%v), want 2e-05", v, ok)
	}
	if v, ok := SampleValue(samples, "go_gc_duration_seconds_count", nil); !ok || v != 4 {
		t.Fatalf("_count = %v (present=%v), want 4", v, ok)
	}
	if v, ok := SampleValue(samples, "go_gc_duration_seconds_sum", nil); !ok || v != 0.0001 {
		t.Fatalf("_sum = %v (present=%v), want 0.0001", v, ok)
	}
	// The quantile label belongs to the quantile samples only.
	for _, s := range samples {
		if s.Name == "go_gc_duration_seconds" {
			if _, ok := s.Labels["quantile"]; !ok {
				t.Fatalf("quantile sample without a quantile label: %+v", s)
			}
			continue
		}
		if _, ok := s.Labels["quantile"]; ok {
			t.Fatalf("%s carries a quantile label: %+v", s.Name, s)
		}
	}
}
