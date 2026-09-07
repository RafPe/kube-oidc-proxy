// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"testing"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
)

func TestReviewRequestAndCacheLookup(t *testing.T) {
	r := newTestRecorder(t)
	r.ReviewRequest(ReviewSAR, ReviewAllow, 3*time.Millisecond)
	r.ReviewRequest(ReviewTokenReview, ReviewTimeout, 10*time.Second)
	r.ReviewRequest(Review("x"), ReviewOutcome("y"), time.Millisecond)
	r.CacheLookup(ReviewSAR, CacheHit)
	r.CacheLookup(ReviewTokenReview, CacheMiss)
	r.CacheLookup(ReviewSAR, CacheBypass)

	g := r.Gatherer()
	if v, _ := metricstest.Value(t, g, nameReviewRequests, map[string]string{"review": "sar", "outcome": "allow"}); v != 1 {
		t.Fatalf("review_requests{sar,allow} = %v", v)
	}
	if n, _ := metricstest.Value(t, g, nameReviewDuration, map[string]string{"review": "tokenreview", "outcome": "timeout"}); n != 1 {
		t.Fatalf("review duration count{tokenreview,timeout} = %v", n)
	}
	if v, _ := metricstest.Value(t, g, nameReviewRequests, map[string]string{"review": "other", "outcome": "other"}); v != 1 {
		t.Fatalf("unknown review/outcome not projected: %v", v)
	}
	for _, res := range []string{"hit", "miss", "bypass"} {
		if n := len(metricstest.LabelValues(t, g, nameCacheLookups, "result")); n != 3 {
			t.Fatalf("cache result values = %d, want 3 (%s)", n, res)
		}
	}
	var nilr *Recorder
	nilr.ReviewRequest(ReviewSAR, ReviewAllow, 0)
	nilr.CacheLookup(ReviewSAR, CacheHit)
}
