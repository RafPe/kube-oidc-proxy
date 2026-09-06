// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview/fake"
)

const (
	metricReviewRequests = "kube_oidc_proxy_review_requests_total"
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

func TestSARCacheBypassCountsOneAPICallPerRequest(t *testing.T) {
	rec := newMetricsRecorder(t)
	s, err := New(fake.New(nil), DefaultTimeout, 0, 0, DefaultMaxHeaderValues, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s.WithMetrics(rec)
	requester := &user.DefaultInfo{Name: "alice"}
	for i := 0; i < 2; i++ {
		if _, err := s.CheckAuthorizedForImpersonation(impersonateUserRequest("jjackson"), requester); err != nil {
			t.Fatal(err)
		}
	}
	g := rec.Gatherer()
	if v, _ := metricstest.Value(t, g, metricCacheLookups, map[string]string{"cache": "sar", "result": "bypass"}); v != 2 {
		t.Fatalf("bypass lookups = %v, want 2 (TTLs are zero)", v)
	}
	if v, _ := metricstest.Value(t, g, metricReviewRequests, map[string]string{"review": "sar", "outcome": "allow"}); v != 2 {
		t.Fatalf("API calls = %v, want 2", v)
	}
}

func TestSARCacheHitDoesNotReachTheAPIServer(t *testing.T) {
	rec := newMetricsRecorder(t)
	s, err := New(fake.New(nil), DefaultTimeout, 10*time.Second, 10*time.Second, DefaultMaxHeaderValues, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s.WithMetrics(rec)
	requester := &user.DefaultInfo{Name: "alice"}
	for i := 0; i < 3; i++ {
		if _, err := s.CheckAuthorizedForImpersonation(impersonateUserRequest("jjackson"), requester); err != nil {
			t.Fatal(err)
		}
	}
	g := rec.Gatherer()
	if v, _ := metricstest.Value(t, g, metricCacheLookups, map[string]string{"cache": "sar", "result": "miss"}); v != 1 {
		t.Fatalf("misses = %v, want 1", v)
	}
	if v, _ := metricstest.Value(t, g, metricCacheLookups, map[string]string{"cache": "sar", "result": "hit"}); v != 2 {
		t.Fatalf("hits = %v, want 2", v)
	}
	if v, _ := metricstest.Value(t, g, metricReviewRequests, map[string]string{"review": "sar", "outcome": "allow"}); v != 1 {
		t.Fatalf("API calls = %v, want 1", v)
	}
	if _, err := s.CheckAuthorizedForImpersonation(impersonateUserRequest("mallory"), requester); err == nil {
		t.Fatal("expected a denial for mallory")
	}
	if v, _ := metricstest.Value(t, g, metricReviewRequests, map[string]string{"review": "sar", "outcome": "deny"}); v != 1 {
		t.Fatalf("denied API calls = %v, want 1", v)
	}
}

// TestCoalescedSARCallersCountOneAPICall runs inside a synctest bubble so the
// interleaving is fixed: synctest.Wait returns only when every caller is
// durably blocked, one inside the reviewer and the rest on its flight. Without
// the bubble a caller could miss the cache, be descheduled past the flight's
// completion and start a second one, which is real behaviour of the
// implementation (there is no cache re-check inside the flight), not a bug in
// the metric.
func TestCoalescedSARCallersCountOneAPICall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rec := newMetricsRecorder(t)
		// The package's existing gateReviewer (subjectaccessreview_test.go)
		// already counts Creates and holds each one open until release is
		// closed. Its non-blocking send on the buffered entered channel can
		// never block a caller, and the flight admits only one caller to
		// Create anyway.
		gate := &gateReviewer{entered: make(chan struct{}, 1), release: make(chan struct{})}
		s, err := New(gate, DefaultTimeout, 10*time.Second, 10*time.Second, DefaultMaxHeaderValues, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		s.WithMetrics(rec)
		requester := &user.DefaultInfo{Name: "alice"}

		const callers = 5
		errs := make(chan error, callers)
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.CheckAuthorizedForImpersonation(impersonateUserRequest("jjackson"), requester)
				errs <- err
			}()
		}

		// Every caller is now durably blocked: one in Create, four on the
		// shared flight's channel.
		synctest.Wait()
		if calls := gate.calls.Load(); calls != 1 {
			t.Fatalf("blocked API calls = %d, want 1", calls)
		}
		close(gate.release)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Errorf("caller failed: %v", err)
			}
		}

		g := rec.Gatherer()
		apiCalls, _ := metricstest.Value(t, g, metricReviewRequests, map[string]string{"review": "sar", "outcome": "allow"})
		misses, _ := metricstest.Value(t, g, metricCacheLookups, map[string]string{"cache": "sar", "result": "miss"})
		hits, _ := metricstest.Value(t, g, metricCacheLookups, map[string]string{"cache": "sar", "result": "hit"})
		if apiCalls != 1 || misses != callers || hits != 0 {
			t.Fatalf("api calls = %v, misses = %v, hits = %v; want 1, %d, 0", apiCalls, misses, hits, callers)
		}
	})
}
