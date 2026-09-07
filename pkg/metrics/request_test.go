// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"fmt"
	"testing"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
)

func TestRequestFinishedCountsAndObservesAShortRequest(t *testing.T) {
	r := newTestRecorder(t)
	r.RequestStarted()
	if v, _ := metricstest.Value(t, r.Gatherer(), nameRequestsInFlight, nil); v != 1 {
		t.Fatalf("in_flight after start = %v, want 1", v)
	}
	r.RequestFinished(RequestObservation{Verb: VerbList, Scope: ScopeNamespace, Status: 200, Termination: "normal", Duration: 30 * time.Millisecond})

	if v, _ := metricstest.Value(t, r.Gatherer(), nameRequestsInFlight, nil); v != 0 {
		t.Fatalf("in_flight after finish = %v, want 0", v)
	}
	v, ok := metricstest.Value(t, r.Gatherer(), nameRequestsTotal,
		map[string]string{"k8s_verb": "list", "scope": "namespace", "code": "200", "termination": "normal"})
	if !ok || v != 1 {
		t.Fatalf("requests_total = %v (present=%v), want 1", v, ok)
	}
	n, ok := metricstest.Value(t, r.Gatherer(), nameRequestDuration, map[string]string{"k8s_verb": "list", "scope": "namespace"})
	if !ok || n != 1 {
		t.Fatalf("duration sample count = %v (present=%v), want 1", n, ok)
	}
}

func TestLongRunningRequestIsGaugedNotTimed(t *testing.T) {
	r := newTestRecorder(t)
	r.RequestStarted()
	r.LongRunningEstablished(VerbWatch, ScopeNamespace)
	if v, _ := metricstest.Value(t, r.Gatherer(), nameLongRunningRequests, map[string]string{"k8s_verb": "watch", "scope": "namespace"}); v != 1 {
		t.Fatalf("long_running after establish = %v, want 1", v)
	}
	r.RequestFinished(RequestObservation{Verb: VerbWatch, Scope: ScopeNamespace, Status: 200, Termination: "client_cancel",
		Duration: time.Hour, LongRunning: true, Established: true})
	if v, _ := metricstest.Value(t, r.Gatherer(), nameLongRunningRequests, map[string]string{"k8s_verb": "watch", "scope": "namespace"}); v != 0 {
		t.Fatalf("long_running after finish = %v, want 0", v)
	}
	if _, ok := metricstest.Value(t, r.Gatherer(), nameRequestDuration, map[string]string{"k8s_verb": "watch"}); ok {
		t.Fatal("a long-running request must not enter the latency histogram")
	}
	if v, _ := metricstest.Value(t, r.Gatherer(), nameRequestsTotal, map[string]string{"k8s_verb": "watch", "termination": "client_cancel"}); v != 1 {
		t.Fatalf("requests_total for the watch = %v, want 1", v)
	}
}

func TestLongRunningNeverEstablishedDoesNotDecrement(t *testing.T) {
	r := newTestRecorder(t)
	r.RequestStarted()
	// A watch refused with 401 never wrote a response, so the gauge was never
	// incremented and must not go negative.
	r.RequestFinished(RequestObservation{Verb: VerbWatch, Scope: ScopeNamespace, Status: 401, Termination: "normal", LongRunning: true})
	if n := metricstest.SeriesCount(t, r.Gatherer(), nameLongRunningRequests); n != 0 {
		t.Fatalf("long_running has %d series, want 0", n)
	}
}

func TestHijackedRequestIsCountedWithCodeNoneAndNotTimed(t *testing.T) {
	r := newTestRecorder(t)
	r.RequestStarted()
	r.LongRunningEstablished(VerbConnect, ScopeResource)
	r.RequestFinished(RequestObservation{Verb: VerbConnect, Scope: ScopeResource, Status: 0, Termination: "hijacked",
		Duration: time.Minute, LongRunning: true, Established: true, Hijacked: true})
	if v, _ := metricstest.Value(t, r.Gatherer(), nameRequestsTotal, map[string]string{"k8s_verb": "connect", "code": "none", "termination": "hijacked"}); v != 1 {
		t.Fatalf("requests_total for the exec = %v, want 1", v)
	}
	if n := metricstest.SeriesCount(t, r.Gatherer(), nameRequestDuration); n != 0 {
		t.Fatalf("duration has %d series, want 0", n)
	}
}

// TestRequestLabelsAreBoundedUnderHostileInput is the cardinality regression
// test: whatever a caller passes, only documented label values are created.
func TestRequestLabelsAreBoundedUnderHostileInput(t *testing.T) {
	r := newTestRecorder(t)
	for i := 0; i < 500; i++ {
		r.RequestStarted()
		r.RequestFinished(RequestObservation{
			Verb:        Verb(fmt.Sprintf("verb-%d", i)),
			Scope:       Scope(fmt.Sprintf("scope-%d", i)),
			Status:      i,
			Termination: fmt.Sprintf("term-%d", i),
		})
	}
	for _, v := range metricstest.LabelValues(t, r.Gatherer(), nameRequestsTotal, "k8s_verb") {
		if v != "other" {
			t.Errorf("k8s_verb leaked %q", v)
		}
	}
	for _, v := range metricstest.LabelValues(t, r.Gatherer(), nameRequestsTotal, "scope") {
		if v != "none" {
			t.Errorf("scope leaked %q", v)
		}
	}
	for _, v := range metricstest.LabelValues(t, r.Gatherer(), nameRequestsTotal, "termination") {
		if v != "other" {
			t.Errorf("termination leaked %q", v)
		}
	}
	// code is bounded by the IANA registry: fewer than 70 distinct values
	// exist in Go's table, and i<500 covers all of them plus "none"/"other".
	if n := len(metricstest.LabelValues(t, r.Gatherer(), nameRequestsTotal, "code")); n > 70 {
		t.Errorf("code has %d distinct values, want at most 70", n)
	}
}
