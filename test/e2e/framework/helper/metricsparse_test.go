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
