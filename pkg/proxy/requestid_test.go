// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/audit"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func TestWithRequestIDMintsAndSetsAuditIDHeader(t *testing.T) {
	p := newTestProxy(t)
	var seenHeader, seenCtx string
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeader = r.Header.Get("Audit-ID")
		seenCtx = reqctx.RequestID(r)
	}))
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil))

	if !uuidRE.MatchString(seenHeader) {
		t.Fatalf("Audit-ID request header = %q, want a UUID", seenHeader)
	}
	if seenCtx != seenHeader {
		t.Fatalf("context request id %q != header %q", seenCtx, seenHeader)
	}
	if got := rw.Header().Get("Audit-ID"); got != seenHeader {
		t.Fatalf("response Audit-ID = %q, want %q", got, seenHeader)
	}
}

func TestWithRequestIDDoesNotTrustClientHeaderFromUntrustedPeer(t *testing.T) {
	p := newTestProxy(t, withConfig(Config{TrustedProxies: []string{"10.0.0.0/8"}}))
	var id, clientID string
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id = reqctx.RequestID(r)
		clientID = reqctx.ClientRequestID(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("Audit-ID", "attacker-chosen-id")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if id == "attacker-chosen-id" {
		t.Fatal("client-supplied Audit-ID adopted from an untrusted peer")
	}
	if clientID != "attacker-chosen-id" {
		t.Fatalf("client_request_id = %q, want the inbound value kept", clientID)
	}
}

func TestWithRequestIDAdoptsHeaderFromTrustedProxy(t *testing.T) {
	p := newTestProxy(t, withConfig(Config{TrustedProxies: []string{"10.0.0.0/8"}}))
	var id string
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { id = reqctx.RequestID(r) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.7:4444"
	req.Header.Set("X-Request-ID", "ingress-trace-1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if id != "ingress-trace-1" {
		t.Fatalf("request id = %q, want ingress-trace-1 from trusted proxy", id)
	}
}

// TestWithRequestIDLeavesTheInboundRequestAlone pins that the filter rewrites
// the request-id headers on a copy, as the other header-rewriting filters do:
// the request it was handed keeps the headers it arrived with.
func TestWithRequestIDLeavesTheInboundRequestAlone(t *testing.T) {
	p := newTestProxy(t)
	var forwarded http.Header
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = r.Header }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Audit-ID", "client-id")
	req.Header.Set("X-Request-ID", "client-trace")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got := req.Header.Get("Audit-ID"); got != "client-id" {
		t.Errorf("inbound Audit-ID = %q, want client-id", got)
	}
	if got := req.Header.Get("X-Request-ID"); got != "client-trace" {
		t.Errorf("inbound X-Request-ID = %q, want client-trace", got)
	}
	if forwarded.Get("Audit-ID") == "client-id" || forwarded.Get("X-Request-ID") != "" {
		t.Errorf("forwarded headers not rewritten: %v", forwarded)
	}
}

func TestWithRequestIDBoundsAndSanitisesInbound(t *testing.T) {
	p := newTestProxy(t, withConfig(Config{TrustedProxies: []string{"10.0.0.0/8"}}))
	var id string
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { id = reqctx.RequestID(r) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.7:4444"
	req.Header.Set("Audit-ID", strings.Repeat("a", 100)+"\nAuFail")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if uuidRE.MatchString(id) {
		return // rejected and minted: acceptable
	}
	if len(id) > 64 || strings.Contains(id, "\n") {
		t.Fatalf("request id not bounded or sanitised: %q", id)
	}
}

func TestBothAuditChainsAdoptTheSameID(t *testing.T) {
	p := newTestProxy(t)
	var fromAudit string
	inner := genericapifilters.WithAuditInit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := audit.AuditIDFrom(r.Context()); ok {
			fromAudit = string(id)
		}
	}))
	var minted string
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		minted = reqctx.RequestID(r)
		inner.ServeHTTP(w, r)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if fromAudit != minted {
		t.Fatalf("audit chain minted %q, filter minted %q; the header must be the channel", fromAudit, minted)
	}
}

// TestWithRequestIDPutsTheIDOnTheContext pins the other half of the filter's
// job: the request carries the correlation id on its context, so a call site
// anywhere downstream gets request_id onto the records that require it
// without threading it through its signature. The id lives on the context
// rather than bound onto a logger, so Emit supplies it only to the events whose
// registry entry requires it.
func TestWithRequestIDPutsTheIDOnTheContext(t *testing.T) {
	p := newTestProxy(t)

	var minted string
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		minted = reqctx.RequestID(r)
		if got := logging.RequestID(r.Context()); got != minted {
			t.Errorf("logging.RequestID = %q, want the minted id %q", got, minted)
		}
		logging.Emit(r.Context(), p.requestLogger,
			logging.EventRequestImpersonationSkipped, slog.String("skip_reason", "test"))
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil))

	rec := p.logs.Only(t, logging.EventRequestImpersonationSkipped)
	if got := rec.String("request_id"); got != minted {
		t.Errorf("request_id = %q, want the minted id %q", got, minted)
	}
	if got := rec.String("component"); got != string(logging.ComponentRequest) {
		t.Errorf("component = %q, want %q", got, logging.ComponentRequest)
	}
}
