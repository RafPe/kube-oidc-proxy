// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

func TestUntrustedForwardedHeadersDroppedIsWarn(t *testing.T) {
	p := newTestProxy(t)
	h := p.withSanitizedForwardHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-Ip", "1.2.3.4")
	req = withTestRequestID(req)
	h.ServeHTTP(httptest.NewRecorder(), req)
	rec := p.logs.Only(t, logging.EventRequestHeadersDropped)
	if rec.String("level") != "WARN" || !strings.Contains(fmt.Sprint(rec["dropped_headers"]), "x-forwarded-for") {
		t.Fatalf("%v", rec)
	}
}

// TestRealIPOnlyDroppedCarriesNoForwardedChain covers the one case in which
// the dropped record has no forwarded chain to report: X-Real-Ip is always
// removed, and the client sent no X-Forwarded-For at all.
func TestRealIPOnlyDroppedCarriesNoForwardedChain(t *testing.T) {
	p := newTestProxy(t)
	h := p.withSanitizedForwardHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1"
	req.Header.Set("X-Real-Ip", "1.2.3.4")
	req = withTestRequestID(req)
	h.ServeHTTP(httptest.NewRecorder(), req)
	rec := p.logs.Only(t, logging.EventRequestHeadersDropped)
	if got := fmt.Sprint(rec["dropped_headers"]); got != "[x-real-ip]" {
		t.Fatalf("dropped_headers = %s, want [x-real-ip]", got)
	}
	if _, ok := rec["forwarded_for_untrusted"]; ok {
		t.Fatalf("record reports a forwarded chain the client never sent: %v", rec)
	}
}

func TestTrustedForwardedHeadersRewritten(t *testing.T) {
	p := newTestProxy(t, withConfig(Config{TrustedProxies: []string{"10.0.0.0/8"}}))
	h := p.withSanitizedForwardHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.7:1"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.9")
	req = withTestRequestID(req)
	h.ServeHTTP(httptest.NewRecorder(), req)
	rec := p.logs.Only(t, logging.EventRequestHeadersRewritten)
	if rec.String("src_ip") != "1.2.3.4" {
		t.Fatal("rewritten record missing resolved src_ip")
	}
	// A rewrite is the trusted-proxy path working as designed, and it fires on
	// every request behind a trusted ingress, so it is diagnostic rather than a
	// warning.
	if rec.String("level") != "DEBUG" {
		t.Fatalf("rewritten record is %s, want DEBUG: %v", rec.String("level"), rec)
	}

	// The same request against a -v=0 logger produces nothing: at the default
	// verbosity an operator sees only the records that need acting on.
	quiet, quietLogs := logtest.New(t, 0)
	q := newTestProxy(t, withConfig(Config{TrustedProxies: []string{"10.0.0.0/8"}}), withLogger(quiet))
	h = q.withSanitizedForwardHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.7:1"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.9")
	req = withTestRequestID(req)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if n := len(quietLogs.ByEvent(logging.EventRequestHeadersRewritten)); n != 0 {
		t.Fatalf("rewritten records at -v=0 = %d, want 0: %s", n, quietLogs.Raw())
	}
}
