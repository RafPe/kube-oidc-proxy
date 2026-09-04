// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// serveWith runs a handler through the two filters that own a request's
// identity and its lifecycle, in the order withHandlers applies them.
func serveWith(t *testing.T, p *fakeProxy, inner http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rw := httptest.NewRecorder()
	p.withRequestID(p.withRequestLifecycle(inner)).ServeHTTP(rw, req)
	return rw
}

// fakeHijackableRW is a ResponseWriter a handler can hijack, which
// httptest.ResponseRecorder deliberately is not.
type fakeHijackableRW struct {
	*fakeRW
	conn net.Conn
}

func newFakeHijackableRW() *fakeHijackableRW {
	client, server := net.Pipe()
	client.Close()
	return &fakeHijackableRW{fakeRW: newFakeRW(), conn: server}
}

func (f *fakeHijackableRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return f.conn, bufio.NewReadWriter(bufio.NewReader(f.conn), bufio.NewWriter(f.conn)), nil
}

func TestCompletedRecordCarriesStatusDurationBytes(t *testing.T) {
	p := newTestProxy(t)
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403); _, _ = w.Write([]byte("nope")) },
		httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil))
	rec := p.logs.Only(t, logging.EventRequestResponseCompleted)
	if s, _ := rec.Int("http_status"); s != 403 {
		t.Fatalf("http_status = %d", s)
	}
	if b, _ := rec.Int("response_bytes"); b != 4 {
		t.Fatalf("response_bytes = %d", b)
	}
	if _, ok := rec.Int("duration_ms"); !ok || rec.String("termination") != "normal" || rec.String("request_id") == "" {
		t.Fatalf("%v", rec)
	}
}

func TestImplicit200OnWrite(t *testing.T) {
	p := newTestProxy(t)
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) },
		httptest.NewRequest(http.MethodGet, "/", nil))
	if s, _ := p.logs.Only(t, logging.EventRequestResponseCompleted).Int("http_status"); s != 200 {
		t.Fatalf("http_status = %d", s)
	}
}

func TestDuplicateWriteHeaderKeepsFirst(t *testing.T) {
	p := newTestProxy(t)
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201); w.WriteHeader(500) },
		httptest.NewRequest(http.MethodGet, "/", nil))
	if s, _ := p.logs.Only(t, logging.EventRequestResponseCompleted).Int("http_status"); s != 201 {
		t.Fatalf("http_status = %d", s)
	}
}

func TestHijackedMarksTerminationAndOmitsBytes(t *testing.T) {
	p := newTestProxy(t)
	rw := newFakeHijackableRW()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	p.withRequestID(p.withRequestLifecycle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := w.(http.Hijacker).Hijack(); err != nil {
			t.Fatal(err)
		}
	}))).ServeHTTP(rw, req)
	rec := p.logs.Only(t, logging.EventRequestResponseCompleted)
	if rec.String("termination") != "hijacked" {
		t.Fatalf("%v", rec)
	}
	if _, has := rec["response_bytes"]; has {
		t.Fatal("response_bytes present on a hijacked response")
	}
}

func TestPanicIsRecordedThenRepanicked(t *testing.T) {
	p := newTestProxy(t)
	defer func() {
		if recover() == nil {
			t.Fatal("panic swallowed")
		}
		if p.logs.Only(t, logging.EventRequestResponseCompleted).String("termination") != "panic" {
			t.Fatal("panic not recorded")
		}
	}()
	serveWith(t, p, func(http.ResponseWriter, *http.Request) { panic("boom") }, httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestResponseStartedOnlyForLongRunning(t *testing.T) {
	p := newTestProxy(t)
	watch := httptest.NewRequest(http.MethodGet, "/api/v1/pods?watch=true", nil)
	watch = watch.WithContext(genericapirequest.WithRequestInfo(watch.Context(),
		&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "watch", Resource: "pods"}))
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, watch)
	if _, ok := p.logs.Only(t, logging.EventRequestResponseStarted).Int("time_to_headers_ms"); !ok {
		t.Fatal("time_to_headers_ms missing")
	}

	p2 := newTestProxy(t)
	serveWith(t, p2, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil))
	if len(p2.logs.ByEvent(logging.EventRequestResponseStarted)) != 0 {
		t.Fatal("response_started emitted for a short request")
	}
}

func TestClientCancelTermination(t *testing.T) {
	p := newTestProxy(t)
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) { cancel(); w.WriteHeader(499) }, req)
	if p.logs.Only(t, logging.EventRequestResponseCompleted).String("termination") != "client_cancel" {
		t.Fatal("client cancel not recorded")
	}
}

// serveChain runs a request through the whole production filter chain, so a
// test can assert on what the order of the filters -- not one filter in
// isolation -- produces.
func serveChain(t *testing.T, p *fakeProxy, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rw := httptest.NewRecorder()
	p.withHandlers(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rw, req)
	return rw
}

// watchRequest is an unauthenticated watch: the chain refuses it with a 401,
// which is enough to exercise every filter that runs before the decision.
func watchRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods?watch=true", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	return req
}

// TestChainResolvesRequestInfoBeforeLifecycle pins that the request is resolved
// into a verb and a resource before the lifecycle filter runs, not only inside
// the audit filters that wrap the reverse proxy. Resolved too late, a watch is
// never recognised as long running and streams for hours with nothing recorded
// until it ends.
func TestChainResolvesRequestInfoBeforeLifecycle(t *testing.T) {
	p := newTestProxy(t)

	if code := serveChain(t, p, watchRequest()).Code; code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if _, ok := p.logs.Only(t, logging.EventRequestResponseStarted).Int("time_to_headers_ms"); !ok {
		t.Fatalf("no response_started for a watch through the full chain: %s", p.logs.Raw())
	}
}

// TestChainResolvesRequestInfoBeforeTheErrorHandler is the other half: the
// error handler runs outside the audit chain, so a denial would otherwise be
// recorded with no k8s_* fields and a query on k8s_resource would see only the
// requests that were allowed through.
func TestChainResolvesRequestInfoBeforeTheErrorHandler(t *testing.T) {
	p := newTestProxy(t)

	serveChain(t, p, watchRequest())

	rec := p.logs.Only(t, logging.EventRequestAccessDecided)
	if rec.String("event") != "AuFail" {
		t.Fatalf("event = %q, want AuFail", rec.String("event"))
	}
	if rec.String("k8s_verb") != "watch" || rec.String("k8s_resource") != "pods" {
		t.Fatalf("denial recorded without request info: %v", rec)
	}
}

// TestUpstreamFailureReachesTheTerminalRecord pins the one piece of plumbing
// neither the lifecycle tests nor the classification test can see on its own.
// The error handler runs several filters below withRequestLifecycle, on a
// request derived from the one the filter holds, so the termination it
// classifies reaches the terminal record only through the shared holder on the
// request context.
func TestUpstreamFailureReachesTheTerminalRecord(t *testing.T) {
	p := newTestProxy(t)
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) {
		// Derived exactly as the filters below the lifecycle one derive it.
		p.handleError(w, r.WithContext(logging.NewContext(r.Context(), p.logger)),
			&net.OpError{Op: "dial", Err: &timeoutErr{}})
	}, httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil))

	rec := p.logs.Only(t, logging.EventRequestResponseCompleted)
	if rec.String("termination") != terminationUpstreamTimeout || rec.String("reason") != reasonUpstreamError {
		t.Fatalf("%v", rec)
	}
	if s, _ := rec.Int("http_status"); s != http.StatusBadGateway {
		t.Fatalf("http_status = %d", s)
	}
}

// TestResponseStartedNotEmittedForAResolvedShortRequest closes the gap the
// negative half of TestResponseStartedOnlyForLongRunning leaves open. That
// request carries no RequestInfo at all, so it only shows that an unresolved
// request is not treated as long running. This one is fully resolved and still
// short, which is the rule actually being asserted: watch yes, get no.
func TestResponseStartedNotEmittedForAResolvedShortRequest(t *testing.T) {
	p := newTestProxy(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
	req = req.WithContext(genericapirequest.WithRequestInfo(req.Context(),
		&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "get", Resource: "pods"}))
	serveWith(t, p, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, req)

	if n := len(p.logs.ByEvent(logging.EventRequestResponseStarted)); n != 0 {
		t.Fatalf("response_started records = %d for a resolved short request: %s", n, p.logs.Raw())
	}
}
