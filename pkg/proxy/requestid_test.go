// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/audit"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func mustCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func TestWithRequestIDMintsAndSetsAuditIDHeader(t *testing.T) {
	p := &Proxy{trustedProxies: nil}
	var seenHeader, seenCtx string
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeader = r.Header.Get("Audit-ID")
		seenCtx = context.RequestID(r)
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
	p := &Proxy{trustedProxies: mustCIDRs(t, "10.0.0.0/8")}
	var id, clientID string
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id = context.RequestID(r)
		clientID = context.ClientRequestID(r)
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
	p := &Proxy{trustedProxies: mustCIDRs(t, "10.0.0.0/8")}
	var id string
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { id = context.RequestID(r) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.7:4444"
	req.Header.Set("X-Request-ID", "ingress-trace-1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if id != "ingress-trace-1" {
		t.Fatalf("request id = %q, want ingress-trace-1 from trusted proxy", id)
	}
}

func TestWithRequestIDBoundsAndSanitisesInbound(t *testing.T) {
	p := &Proxy{trustedProxies: mustCIDRs(t, "10.0.0.0/8")}
	var id string
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { id = context.RequestID(r) }))
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
	p := &Proxy{}
	var fromAudit string
	inner := genericapifilters.WithAuditInit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := audit.AuditIDFrom(r.Context()); ok {
			fromAudit = string(id)
		}
	}))
	var minted string
	h := p.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		minted = context.RequestID(r)
		inner.ServeHTTP(w, r)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if fromAudit != minted {
		t.Fatalf("audit chain minted %q, filter minted %q; the header must be the channel", fromAudit, minted)
	}
}
