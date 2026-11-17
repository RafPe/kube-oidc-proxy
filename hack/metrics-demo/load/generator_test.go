// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"testing"

	"github.com/rafpe/kube-oidc-proxy/internal/devkit/promtext"
)

// TestSeriesSumTotalsMatchingSeriesOnly pins the delta helper: every series of
// the family whose labels include the given pairs is summed, and nothing else.
func TestSeriesSumTotalsMatchingSeriesOnly(t *testing.T) {
	samples := []promtext.Sample{
		{Name: "kube_oidc_proxy_cache_lookups_total", Labels: map[string]string{"cache": "sar", "result": "miss"}, Value: 2},
		{Name: "kube_oidc_proxy_cache_lookups_total", Labels: map[string]string{"cache": "sar", "result": "miss", "pod": "b"}, Value: 3},
		{Name: "kube_oidc_proxy_cache_lookups_total", Labels: map[string]string{"cache": "sar", "result": "hit"}, Value: 7},
		{Name: "kube_oidc_proxy_cache_lookups_total", Labels: map[string]string{"cache": "tokenreview", "result": "miss"}, Value: 11},
		{Name: "other_total", Labels: map[string]string{"cache": "sar", "result": "miss"}, Value: 13},
	}

	if got := seriesSum(samples, "kube_oidc_proxy_cache_lookups_total", sarMissLabels()); got != 5 {
		t.Fatalf("seriesSum = %v, want 5", got)
	}
	if got := seriesSum(samples, "kube_oidc_proxy_cache_lookups_total", nil); got != 23 {
		t.Fatalf("seriesSum with no label filter = %v, want 23", got)
	}
	if got := seriesSum(samples, "missing", nil); got != 0 {
		t.Fatalf("seriesSum of an absent family = %v, want 0", got)
	}
}
