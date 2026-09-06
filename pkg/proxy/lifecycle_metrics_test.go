// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
)

const (
	metricRequestsTotal   = "kube_oidc_proxy_requests_total"
	metricRequestDuration = "kube_oidc_proxy_request_duration_seconds"
	metricInFlight        = "kube_oidc_proxy_requests_in_flight"
	metricLongRunning     = "kube_oidc_proxy_long_running_requests"
)

// resourceRequest builds a request already resolved into a RequestInfo, as
// auditor.WithRequestInfo would have done ahead of the lifecycle filter.
func resourceRequest(method, path string, info *genericapirequest.RequestInfo) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	return req.WithContext(genericapirequest.WithRequestInfo(req.Context(), info))
}

func TestLifecycleCountsAShortRequestOnce(t *testing.T) {
	p := newTestProxy(t)
	req := resourceRequest(http.MethodGet, "/api/v1/namespaces/a/pods",
		&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "list", Resource: "pods", Namespace: "a"})
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }, req)

	g := p.metrics.Gatherer()
	if v, ok := metricstest.Value(t, g, metricRequestsTotal,
		map[string]string{"k8s_verb": "list", "scope": "namespace", "code": "200", "termination": "normal"}); !ok || v != 1 {
		t.Fatalf("requests_total = %v (present=%v), want 1", v, ok)
	}
	if n, _ := metricstest.Value(t, g, metricRequestDuration, map[string]string{"k8s_verb": "list", "scope": "namespace"}); n != 1 {
		t.Fatalf("duration sample count = %v, want 1", n)
	}
	if v, _ := metricstest.Value(t, g, metricInFlight, nil); v != 0 {
		t.Fatalf("in_flight after the request = %v, want 0", v)
	}
}

func TestLifecycleInFlightIsOneWhileTheHandlerRuns(t *testing.T) {
	p := newTestProxy(t)
	var during float64
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) {
		during, _ = metricstest.Value(t, p.metrics.Gatherer(), metricInFlight, nil)
	}, httptest.NewRequest(http.MethodGet, "/", nil))
	if during != 1 {
		t.Fatalf("in_flight during the handler = %v, want 1", during)
	}
}

func TestLifecycleWatchIsGaugedOnHeadersAndNeverTimed(t *testing.T) {
	p := newTestProxy(t)
	req := resourceRequest(http.MethodGet, "/api/v1/namespaces/a/pods?watch=true",
		&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "watch", Resource: "pods", Namespace: "a"})
	var afterHeaders float64
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		afterHeaders, _ = metricstest.Value(t, p.metrics.Gatherer(), metricLongRunning, map[string]string{"k8s_verb": "watch", "scope": "namespace"})
	}, req)
	if afterHeaders != 1 {
		t.Fatalf("long_running after WriteHeader = %v, want 1", afterHeaders)
	}
	g := p.metrics.Gatherer()
	if v, _ := metricstest.Value(t, g, metricLongRunning, map[string]string{"k8s_verb": "watch", "scope": "namespace"}); v != 0 {
		t.Fatalf("long_running after the watch ended = %v, want 0", v)
	}
	if _, ok := metricstest.Value(t, g, metricRequestDuration, map[string]string{"k8s_verb": "watch"}); ok {
		t.Fatal("a watch entered the latency histogram")
	}
	if v, _ := metricstest.Value(t, g, metricRequestsTotal, map[string]string{"k8s_verb": "watch", "code": "200", "termination": "normal"}); v != 1 {
		t.Fatalf("requests_total for the watch = %v, want 1", v)
	}
}

func TestLifecycleRefusedWatchNeverTouchesTheGauge(t *testing.T) {
	p := newTestProxy(t)
	req := resourceRequest(http.MethodGet, "/api/v1/pods?watch=true",
		&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "watch", Resource: "pods"})
	var during float64
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
		during, _ = metricstest.Value(t, p.metrics.Gatherer(), metricLongRunning, map[string]string{"k8s_verb": "watch", "scope": "cluster"})
	}, req)
	// A 401 wrote headers but opened no stream: the gauge is never touched,
	// so no series exists for it, and the request is counted with its code.
	if during != 0 {
		t.Fatalf("long_running during a refused watch = %v, want 0", during)
	}
	g := p.metrics.Gatherer()
	if n := metricstest.SeriesCount(t, g, metricLongRunning); n != 0 {
		t.Fatalf("long_running has %d series after a refused watch, want 0", n)
	}
	if v, _ := metricstest.Value(t, g, metricRequestsTotal, map[string]string{"k8s_verb": "watch", "scope": "cluster", "code": "401"}); v != 1 {
		t.Fatalf("requests_total{code=401} = %v, want 1", v)
	}
}

// TestLifecycleOnlySuccessStatusesEstablishAStream table-tests the status
// classes: 2xx and 101 open a stream, everything else does not.
func TestLifecycleOnlySuccessStatusesEstablishAStream(t *testing.T) {
	tests := map[int]bool{
		200: true, 204: true, 101: true,
		301: false, 302: false, 304: false, 307: false, 308: false,
		401: false, 403: false, 500: false, 502: false,
	}
	for code, want := range tests {
		t.Run(http.StatusText(code), func(t *testing.T) {
			p := newTestProxy(t)
			req := resourceRequest(http.MethodGet, "/api/v1/namespaces/a/pods?watch=true",
				&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "watch", Resource: "pods", Namespace: "a"})
			var during float64
			serveWith(t, p, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
				during, _ = metricstest.Value(t, p.metrics.Gatherer(), metricLongRunning, map[string]string{"k8s_verb": "watch", "scope": "namespace"})
			}, req)
			if got := during == 1; got != want {
				t.Fatalf("status %d established a stream = %v, want %v", code, got, want)
			}
			if n := metricstest.SeriesCount(t, p.metrics.Gatherer(), metricLongRunning); want && n == 0 || !want && n != 0 {
				t.Fatalf("status %d: long_running series after the request = %d", code, n)
			}
		})
	}
}

func TestLifecycleHijackEstablishesAndEndsAStream(t *testing.T) {
	p := newTestProxy(t)
	rw := newFakeHijackableRW()
	req := resourceRequest(http.MethodPost, "/api/v1/namespaces/a/pods/p/exec",
		&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "connect", Resource: "pods", Subresource: "exec", Namespace: "a", Name: "p"})
	var afterHijack float64
	p.withRequestID(p.withRequestLifecycle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := w.(http.Hijacker).Hijack(); err != nil {
			t.Fatal(err)
		}
		afterHijack, _ = metricstest.Value(t, p.metrics.Gatherer(), metricLongRunning, map[string]string{"k8s_verb": "connect", "scope": "resource"})
	}))).ServeHTTP(rw, req)
	if afterHijack != 1 {
		t.Fatalf("long_running after Hijack = %v, want 1", afterHijack)
	}
	g := p.metrics.Gatherer()
	if v, _ := metricstest.Value(t, g, metricLongRunning, map[string]string{"k8s_verb": "connect", "scope": "resource"}); v != 0 {
		t.Fatalf("long_running after the exec ended = %v, want 0", v)
	}
	if v, _ := metricstest.Value(t, g, metricRequestsTotal, map[string]string{"k8s_verb": "connect", "code": "none", "termination": "hijacked"}); v != 1 {
		t.Fatalf("requests_total for the exec = %v, want 1", v)
	}
	if n := metricstest.SeriesCount(t, g, metricRequestDuration); n != 0 {
		t.Fatalf("duration has %d series after a hijack, want 0", n)
	}
}

// TestLifecycleAbortedWatchReleasesTheGauge covers the way httputil.ReverseProxy
// ends a stream whose upstream broke: it panics with http.ErrAbortHandler
// after the headers went out. The gauge must be released and the request
// labelled upstream_reset, exactly as the terminal record classifies it.
func TestLifecycleAbortedWatchReleasesTheGauge(t *testing.T) {
	p := newTestProxy(t)
	req := resourceRequest(http.MethodGet, "/api/v1/namespaces/a/pods?watch=true",
		&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "watch", Resource: "pods", Namespace: "a"})
	func() {
		defer func() {
			// The abort is re-panicked unchanged so the server's own recovery
			// still sees the sentinel.
			if got := recover(); got != http.ErrAbortHandler {
				t.Errorf("re-panicked value = %v, want http.ErrAbortHandler", got)
			}
		}()
		serveWith(t, p, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			panic(http.ErrAbortHandler)
		}, req)
	}()
	g := p.metrics.Gatherer()
	if v, _ := metricstest.Value(t, g, metricLongRunning, map[string]string{"k8s_verb": "watch", "scope": "namespace"}); v != 0 {
		t.Fatalf("long_running after an aborted watch = %v, want 0", v)
	}
	if v, _ := metricstest.Value(t, g, metricInFlight, nil); v != 0 {
		t.Fatalf("in_flight after an aborted watch = %v, want 0", v)
	}
	if _, timed := metricstest.Value(t, g, metricRequestDuration, map[string]string{"k8s_verb": "watch"}); timed {
		t.Fatal("an aborted watch entered the latency histogram")
	}
	if v, _ := metricstest.Value(t, g, metricRequestsTotal, map[string]string{"k8s_verb": "watch", "termination": "upstream_reset"}); v != 1 {
		t.Fatalf("requests_total{watch,upstream_reset} = %v, want 1", v)
	}
}

// TestLifecycleFlushEstablishesAWatch mirrors the log's flush path: a watch
// that flushes before writing anything has started its response with the
// implicit 200, and that is when the stream counts as open.
func TestLifecycleFlushEstablishesAWatch(t *testing.T) {
	p := newTestProxy(t)
	req := resourceRequest(http.MethodGet, "/api/v1/namespaces/a/pods?watch=true",
		&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "watch", Resource: "pods", Namespace: "a"})
	var afterFlush float64
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		afterFlush, _ = metricstest.Value(t, p.metrics.Gatherer(), metricLongRunning, map[string]string{"k8s_verb": "watch", "scope": "namespace"})
	}, req)
	if afterFlush != 1 {
		t.Fatalf("long_running after Flush = %v, want 1", afterFlush)
	}
	if v, _ := metricstest.Value(t, p.metrics.Gatherer(), metricLongRunning, map[string]string{"k8s_verb": "watch", "scope": "namespace"}); v != 0 {
		t.Fatalf("long_running after the watch ended = %v, want 0", v)
	}
}

func TestLifecyclePanicStillDecrementsInFlight(t *testing.T) {
	p := newTestProxy(t)
	func() {
		defer func() { _ = recover() }()
		serveWith(t, p, func(http.ResponseWriter, *http.Request) { panic("boom") }, httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	g := p.metrics.Gatherer()
	if v, _ := metricstest.Value(t, g, metricInFlight, nil); v != 0 {
		t.Fatalf("in_flight after a panic = %v, want 0", v)
	}
	if v, _ := metricstest.Value(t, g, metricRequestsTotal, map[string]string{"termination": "panic", "code": "none"}); v != 1 {
		t.Fatalf("requests_total{termination=panic} = %v, want 1", v)
	}
}

func TestLifecycleClientCancelAndUpstreamTerminationsAreLabelled(t *testing.T) {
	p := newTestProxy(t)
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) { cancel(); w.WriteHeader(499) }, req)
	if v, _ := metricstest.Value(t, p.metrics.Gatherer(), metricRequestsTotal, map[string]string{"termination": "client_cancel"}); v != 1 {
		t.Fatalf("requests_total{termination=client_cancel} = %v, want 1", v)
	}
}

// TestLifecycleLabelsAreBoundedUnderHostileRequests drives the filter with
// paths and methods a client controls and asserts the label domain does not
// grow beyond the documented sets. This is the regression test for the
// cardinality property; a future label that leaks a client string fails here.
func TestLifecycleLabelsAreBoundedUnderHostileRequests(t *testing.T) {
	p := newTestProxy(t)
	for i := 0; i < 200; i++ {
		req := httptest.NewRequest(fmt.Sprintf("M%d", i), fmt.Sprintf("/apis/g%d/v1/r%d/n%d", i, i, i), nil)
		// Resolve as the audit filter would: an unknown group prefix parses as
		// a non-resource request carrying the raw method as its verb.
		req = req.WithContext(genericapirequest.WithRequestInfo(req.Context(),
			&genericapirequest.RequestInfo{IsResourceRequest: false, Verb: fmt.Sprintf("m%d", i), Path: req.URL.Path}))
		serveWith(t, p, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200 + i%400) }, req)
	}
	g := p.metrics.Gatherer()
	for _, v := range metricstest.LabelValues(t, g, metricRequestsTotal, "k8s_verb") {
		if v != "other" {
			t.Errorf("k8s_verb leaked %q", v)
		}
	}
	for _, v := range metricstest.LabelValues(t, g, metricRequestsTotal, "scope") {
		if v != "none" {
			t.Errorf("scope leaked %q", v)
		}
	}
	if n := metricstest.SeriesCount(t, g, metricRequestsTotal); n > 70 {
		t.Errorf("requests_total grew to %d series under hostile input", n)
	}
}
