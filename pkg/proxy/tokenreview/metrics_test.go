// Copyright Jetstack Ltd. See LICENSE for details.
package tokenreview

import (
	"context"
	"errors"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/tokenreview/fake"
)

const (
	metricReviewRequests = "kube_oidc_proxy_review_requests_total"
	metricReviewDuration = "kube_oidc_proxy_review_request_duration_seconds"
	metricCacheLookups   = "kube_oidc_proxy_cache_lookups_total"
)

func newMetricsRecorder(t *testing.T) *metrics.Recorder {
	t.Helper()
	r, err := metrics.New(metrics.BuildInfo{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLiveReviewOutcomesAreCounted(t *testing.T) {
	tests := map[string]struct {
		create  func(*authv1.TokenReview) (*authv1.TokenReview, error)
		outcome string
	}{
		"authenticated":   {func(*authv1.TokenReview) (*authv1.TokenReview, error) { return authenticatedReview(), nil }, "allow"},
		"unauthenticated": {func(*authv1.TokenReview) (*authv1.TokenReview, error) { return unauthenticatedReview(), nil }, "deny"},
		"status error": {func(*authv1.TokenReview) (*authv1.TokenReview, error) {
			return &authv1.TokenReview{Status: authv1.TokenReviewStatus{Error: "boom"}}, nil
		}, "error"},
		"transport error": {func(*authv1.TokenReview) (*authv1.TokenReview, error) { return nil, errors.New("dial") }, "error"},
		"deadline":        {func(*authv1.TokenReview) (*authv1.TokenReview, error) { return nil, context.DeadlineExceeded }, "timeout"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := newMetricsRecorder(t)
			tr := (&TokenReview{reviewRequester: &fake.FakeReviewer{CreateFn: tc.create}}).WithMetrics(rec)
			_, _, _ = tr.AuthenticateToken(testRequestContext(), "tok")
			if v, _ := metricstest.Value(t, rec.Gatherer(), metricReviewRequests, map[string]string{"review": "tokenreview", "outcome": tc.outcome}); v != 1 {
				t.Fatalf("review_requests{tokenreview,%s} = %v, want 1", tc.outcome, v)
			}
			if n, _ := metricstest.Value(t, rec.Gatherer(), metricReviewDuration, map[string]string{"review": "tokenreview", "outcome": tc.outcome}); n != 1 {
				t.Fatalf("review duration count = %v, want 1", n)
			}
		})
	}
}

func TestCachedReviewCountsHitsAndMissesButOneAPICall(t *testing.T) {
	rec := newMetricsRecorder(t)
	tr := (&TokenReview{reviewRequester: &fake.FakeReviewer{CreateFn: func(*authv1.TokenReview) (*authv1.TokenReview, error) {
		return authenticatedReview(), nil
	}}}).WithMetrics(rec)
	c := newCachedTokenReview(tr, 10*time.Second, 10*time.Second, 16)
	for i := 0; i < 3; i++ {
		if _, ok, err := c.AuthenticateToken(testRequestContext(), "tok"); !ok || err != nil {
			t.Fatalf("call %d: ok=%v err=%v", i, ok, err)
		}
	}
	g := rec.Gatherer()
	if v, _ := metricstest.Value(t, g, metricCacheLookups, map[string]string{"cache": "tokenreview", "result": "miss"}); v != 1 {
		t.Fatalf("cache misses = %v, want 1", v)
	}
	if v, _ := metricstest.Value(t, g, metricCacheLookups, map[string]string{"cache": "tokenreview", "result": "hit"}); v != 2 {
		t.Fatalf("cache hits = %v, want 2", v)
	}
	if v, _ := metricstest.Value(t, g, metricReviewRequests, map[string]string{"review": "tokenreview", "outcome": "allow"}); v != 1 {
		t.Fatalf("API calls = %v, want 1: hits must not reach the API server", v)
	}
}
