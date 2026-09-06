// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
)

func testBuild() BuildInfo {
	return BuildInfo{Version: "v9.9.9-test", Revision: "abcdef0", GoVersion: "go1.26.6"}
}

func newTestRecorder(t testing.TB) *Recorder {
	t.Helper()
	r, err := New(testBuild())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func TestNewExposesBuildInfoAndRuntimeCollectors(t *testing.T) {
	r := newTestRecorder(t)
	v, ok := metricstest.Value(t, r.Gatherer(), "kube_oidc_proxy_build_info",
		map[string]string{"version": "v9.9.9-test", "revision": "abcdef0", "go_version": "go1.26.6"})
	if !ok || v != 1 {
		t.Fatalf("build_info = %v (present=%v), want 1", v, ok)
	}
	families, err := r.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var goSeen, processSeen bool
	for _, f := range families {
		switch {
		case strings.HasPrefix(f.GetName(), "go_"):
			goSeen = true
		case strings.HasPrefix(f.GetName(), "process_"):
			processSeen = true
		}
	}
	if !goSeen || !processSeen {
		t.Fatalf("go collector seen=%v, process collector seen=%v; want both", goSeen, processSeen)
	}
}

func TestEveryCatalogueEntryHasAStabilityPrefixAndTheNamespace(t *testing.T) {
	for _, s := range Catalogue() {
		if !strings.HasPrefix(s.Name, Namespace+"_") {
			t.Errorf("%s: not under the %s namespace", s.Name, Namespace)
		}
		if s.Stability != "STABLE" && s.Stability != "ALPHA" {
			t.Errorf("%s: stability %q, want STABLE or ALPHA", s.Name, s.Stability)
		}
		if s.Help == "" || strings.HasPrefix(s.Help, "[") {
			t.Errorf("%s: help %q must be non-empty and must not repeat the stability prefix", s.Name, s.Help)
		}
		switch s.Type {
		case "counter", "gauge", "histogram":
		default:
			t.Errorf("%s: type %q", s.Name, s.Type)
		}
	}
}

// TestGatherAndLintIsClean runs promlint over everything the recorder exports,
// so a missing _total suffix or a non-base unit fails here rather than in
// review. A vector with no series is not gathered, so every collector is
// touched first; Task 17 repeats the lint after the real observation methods.
func TestGatherAndLintIsClean(t *testing.T) {
	r := newTestRecorder(t)
	touchEveryCollector(r)
	problems, err := testutil.GatherAndLint(r.Gatherer())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("promlint: %s: %s", p.Metric, p.Text)
	}
}

func TestHandlerServesOnlyGetMetrics(t *testing.T) {
	r := newTestRecorder(t)
	h := r.Handler(slog.New(slog.DiscardHandler))

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rw.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200: %s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "kube_oidc_proxy_build_info{") {
		t.Fatalf("exposition lacks build_info:\n%s", rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "# HELP kube_oidc_proxy_build_info [STABLE] ") {
		t.Fatalf("help string lacks the stability prefix:\n%s", rw.Body.String())
	}

	// A GET pattern also admits HEAD, which a load balancer health check may
	// send; it is harmless and answered without a body.
	rw = httptest.NewRecorder()
	h.ServeHTTP(rw, httptest.NewRequest(http.MethodHead, "/metrics", nil))
	if rw.Code != http.StatusOK {
		t.Fatalf("HEAD /metrics = %d, want 200", rw.Code)
	}

	rw = httptest.NewRecorder()
	h.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if rw.Code != http.StatusMethodNotAllowed || rw.Header().Get("Allow") == "" {
		t.Fatalf("POST /metrics = %d (Allow %q), want 405 with an Allow header", rw.Code, rw.Header().Get("Allow"))
	}

	var nilr *Recorder
	rw = httptest.NewRecorder()
	nilr.Handler(nil).ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rw.Code != http.StatusNotFound {
		t.Fatalf("nil recorder handler = %d, want 404", rw.Code)
	}

	for _, path := range []string{"/", "/debug/pprof/", "/metrics/", "/healthz"} {
		rw = httptest.NewRecorder()
		h.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, path, nil))
		if rw.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", path, rw.Code)
		}
	}
}

// touchEveryCollector creates one series on every vector so a Gather sees
// every first-party family. It uses the collectors directly, not the
// observation methods, so the contract tests in this file do not depend on
// methods later tasks define.
func touchEveryCollector(r *Recorder) {
	r.requestsTotal.WithLabelValues("get", "resource", "200", "normal").Inc()
	r.requestDuration.WithLabelValues("get", "resource").Observe(0.001)
	r.requestsInFlight.Set(0)
	r.longRunningRequests.WithLabelValues("watch", "namespace").Set(0)
	r.authnAttempts.WithLabelValues("oidc", "accepted").Inc()
	r.accessDecisions.WithLabelValues("oidc", "allow", "").Inc()
	r.reviewRequests.WithLabelValues("sar", "allow").Inc()
	r.reviewDuration.WithLabelValues("sar", "allow").Observe(0.001)
	r.cacheLookups.WithLabelValues("sar", "miss").Inc()
	r.issuerInitialized.WithLabelValues("idp.example.com").Set(1)
	r.ready.Set(1)
	r.auditFailures.WithLabelValues("run").Inc()
}

// TestHistogramBucketsAreTheContract pins the bucket boundaries: they are
// published in docs/metrics.md and a change is a breaking change. The
// expected lists are literals on purpose; comparing against the package's own
// slices would let an edit change both sides at once.
func TestHistogramBucketsAreTheContract(t *testing.T) {
	r := newTestRecorder(t)
	touchEveryCollector(r)

	families, err := r.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]float64{
		nameRequestDuration: {0.005, 0.025, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2, 3, 4, 5, 6, 8, 10, 15, 20, 30, 45, 60},
		nameReviewDuration:  {0.0001, 0.0003, 0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1, 5, 10, 15, 30},
	}
	for _, f := range families {
		bounds, ok := want[f.GetName()]
		if !ok {
			continue
		}
		var got []float64
		for _, b := range f.GetMetric()[0].GetHistogram().GetBucket() {
			got = append(got, b.GetUpperBound())
		}
		if !slices.Equal(got, bounds) {
			t.Errorf("%s buckets = %v, want %v", f.GetName(), got, bounds)
		}
		delete(want, f.GetName())
	}
	if len(want) != 0 {
		t.Errorf("histograms not gathered: %v", want)
	}
}

// blockingCollector holds every Collect until released, so a test can pile
// scrapes up on the handler.
type blockingCollector struct {
	desc    *prometheus.Desc
	entered chan struct{}
	release chan struct{}
}

func (c *blockingCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }
func (c *blockingCollector) Collect(ch chan<- prometheus.Metric) {
	c.entered <- struct{}{}
	<-c.release
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, 1)
}

// TestHandlerBoundsConcurrentScrapes proves the scrape-DoS bound: with
// maxScrapesInFlight scrapes blocked in Gather, the next one is answered 503
// immediately rather than queued.
func TestHandlerBoundsConcurrentScrapes(t *testing.T) {
	r := newTestRecorder(t)
	bc := &blockingCollector{
		desc:    prometheus.NewDesc("test_blocking", "blocks", nil, nil),
		entered: make(chan struct{}, maxScrapesInFlight),
		release: make(chan struct{}),
	}
	if err := r.reg.Register(bc); err != nil {
		t.Fatal(err)
	}
	h := r.Handler(slog.New(slog.DiscardHandler))

	codes := make(chan int, maxScrapesInFlight)
	for i := 0; i < maxScrapesInFlight; i++ {
		go func() {
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			codes <- rw.Code
		}()
	}
	for i := 0; i < maxScrapesInFlight; i++ {
		select {
		case <-bc.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("scrapes did not reach the collector")
		}
	}

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("scrape beyond the in-flight bound = %d, want 503", rw.Code)
	}

	close(bc.release)
	for i := 0; i < maxScrapesInFlight; i++ {
		if code := <-codes; code != http.StatusOK {
			t.Errorf("blocked scrape finished with %d, want 200", code)
		}
	}
}

func TestNilRecorderIsANoOp(t *testing.T) {
	var r *Recorder
	// Every observation method must tolerate a nil receiver; the ones defined
	// in later tasks are added to this list as they land.
	r.RequestStarted()
	r.LongRunningEstablished(VerbWatch, ScopeNamespace)
	r.RequestFinished(RequestObservation{})
	if r.Gatherer() != nil {
		t.Fatal("nil recorder must have a nil gatherer")
	}
}
