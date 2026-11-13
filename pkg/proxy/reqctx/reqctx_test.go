// Copyright Jetstack Ltd. See LICENSE for details.
package reqctx

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

// TestWithResolvedClient pins what the context stores: the client IP and
// headers it is handed, and the raw inbound chain from the request as it
// arrived, while the caller's request keeps its own header map.
func TestWithResolvedClient(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "10.0.0.5:5555",
		Header: http.Header{
			"X-Forwarded-For": []string{"1.2.3.4, 10.0.0.9"},
			"X-Real-Ip":       []string{"9.9.9.9"},
		},
	}
	sanitized := http.Header{"X-Forwarded-For": []string{"1.2.3.4"}}

	out := WithResolvedClient(req, "1.2.3.4", sanitized)

	if got := ClientIP(out); got != "1.2.3.4" {
		t.Errorf("ClientIP = %q, want 1.2.3.4", got)
	}
	if got := OriginalForwardedFor(out); got != "1.2.3.4, 10.0.0.9" {
		t.Errorf("OriginalForwardedFor = %q, want the inbound chain", got)
	}
	if !reflect.DeepEqual(out.Header, sanitized) {
		t.Errorf("derived headers = %v, want %v", out.Header, sanitized)
	}
	if got := req.Header.Get("X-Real-Ip"); got != "9.9.9.9" {
		t.Errorf("caller's X-Real-Ip = %q, want untouched 9.9.9.9", got)
	}
}

// TestClientIP_UnresolvedRequestReportsPeer pins the fallback for a request
// that never passed through WithResolvedClient: the direct peer, which is what
// the contract resolves to when no proxy is trusted, so a caller outside the
// filter chain never sees a forwarded address it did not validate.
func TestClientIP_UnresolvedRequestReportsPeer(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "203.0.113.7:5555",
		Header:     http.Header{"X-Forwarded-For": []string{"1.2.3.4"}},
	}

	if got := ClientIP(req); got != "203.0.113.7" {
		t.Errorf("ClientIP = %q, want %q", got, "203.0.113.7")
	}
	if got := OriginalForwardedFor(req); got != "" {
		t.Errorf("OriginalForwardedFor = %q on an unresolved request, want empty", got)
	}
}

// TestRequestScopedIDAccessors covers the round trip of the correlation-id and
// issuer-name accessors, including the zero value on a request that never
// passed the request-id filter.
func TestRequestScopedIDAccessors(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if got := RequestID(req); got != "" {
		t.Errorf("RequestID on a bare request = %q, want empty", got)
	}
	if got := ClientRequestID(req); got != "" {
		t.Errorf("ClientRequestID on a bare request = %q, want empty", got)
	}
	if got := IssuerName(req); got != "" {
		t.Errorf("IssuerName on a bare request = %q, want empty", got)
	}

	req = WithRequestID(req, "minted-1")
	req = WithClientRequestID(req, "client-1")
	req = WithIssuerName(req, "corp-idp")

	if got := RequestID(req); got != "minted-1" {
		t.Errorf("RequestID = %q, want minted-1", got)
	}
	if got := ClientRequestID(req); got != "client-1" {
		t.Errorf("ClientRequestID = %q, want client-1", got)
	}
	if got := IssuerName(req); got != "corp-idp" {
		t.Errorf("IssuerName = %q, want corp-idp", got)
	}
}

// TestHoldersAreSharedWithDerivedRequests pins the holder contract the
// lifecycle filter relies on: a holder installed on a request is written
// through a request derived from it further down the chain, and the write is
// visible on the request that installed it.
func TestHoldersAreSharedWithDerivedRequests(t *testing.T) {
	parent := WithDecisionHolder(WithTerminationHolder(httptest.NewRequest(http.MethodGet, "/", nil)))
	child := parent.WithContext(genericapirequest.WithUser(parent.Context(), &user.DefaultInfo{Name: "alice"}))

	MarkDecisionRecorded(child)
	MarkTermination(child, metrics.TerminationUpstreamReset, metrics.ReasonUpstreamError)

	if !DecisionRecorded(parent) {
		t.Error("a decision marked on a derived request is not visible on the parent")
	}
	want := TerminationRecord{Kind: metrics.TerminationUpstreamReset, Reason: metrics.ReasonUpstreamError}
	if got := Termination(parent); got != want {
		t.Errorf("Termination(parent) = %+v, want %+v", got, want)
	}
}

// TestHolderlessRequestsAreSafe pins the other half of the holder contract: a
// request that never passed the lifecycle filter can be marked without a
// panic, and reads back the zero values, so its decision is still recorded.
func TestHolderlessRequestsAreSafe(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	MarkDecisionRecorded(req)
	MarkTermination(req, metrics.TerminationUpstreamReset, metrics.ReasonUpstreamError)

	if DecisionRecorded(req) {
		t.Error("DecisionRecorded = true on a request with no holder")
	}
	if got := Termination(req); got != (TerminationRecord{}) {
		t.Errorf("Termination = %+v on a request with no holder, want the zero value", got)
	}
	if got := AuthMethod(req); got != metrics.AuthMethodNone {
		t.Errorf("AuthMethod = %q on a request that never authenticated, want %q", got, metrics.AuthMethodNone)
	}
	if got := ForwardDecision(req); got != nil {
		t.Errorf("ForwardDecision = %+v before any filter decided it, want nil", got)
	}
}

func TestAuthMethodRoundTrip(t *testing.T) {
	req := WithAuthMethod(httptest.NewRequest(http.MethodGet, "/", nil), metrics.AuthMethodOIDC)
	if got := AuthMethod(req); got != metrics.AuthMethodOIDC {
		t.Errorf("AuthMethod = %q, want %q", got, metrics.AuthMethodOIDC)
	}
}

// TestWithForwardDecisionSetsUserOnlyWhenImpersonating pins that the
// impersonated identity replaces the request's user, which is what the audit
// chain records, while a request forwarded as itself keeps its own.
func TestWithForwardDecisionSetsUserOnlyWhenImpersonating(t *testing.T) {
	alice := &user.DefaultInfo{Name: "alice"}
	bob := &user.DefaultInfo{Name: "bob"}

	tests := map[string]struct {
		rec      *ForwardDecisionRecord
		wantUser string
	}{
		"impersonating someone": {
			rec:      &ForwardDecisionRecord{Mode: ForwardImpersonating, InboundUser: alice, ImpersonatedUser: bob},
			wantUser: "bob",
		},
		"forwarded as itself": {
			rec:      &ForwardDecisionRecord{Mode: ForwardImpersonating, InboundUser: alice},
			wantUser: "alice",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req = req.WithContext(genericapirequest.WithUser(req.Context(), alice))

			req = WithForwardDecision(req, tc.rec)

			if got := ForwardDecision(req); got != tc.rec {
				t.Errorf("ForwardDecision = %+v, want the record that was set", got)
			}
			u, _ := genericapirequest.UserFrom(req.Context())
			if u.GetName() != tc.wantUser {
				t.Errorf("request user = %q, want %q", u.GetName(), tc.wantUser)
			}
		})
	}
}
