// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	fakesubjectaccessreview "github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview/fake"
)

// TestWithImpersonateRequestDoesNotMutateAuthenticatorUser is the regression
// test for issue #52: request enrichment must never mutate the groups slice or
// extra map owned by the authenticator. The user is built so that the unfixed
// code would observably corrupt shared state — the groups slice has spare
// capacity (so an in-place append writes into the shared backing array) and the
// extra map both gains new keys and has an existing value slice extended.
func TestWithImpersonateRequestDoesNotMutateAuthenticatorUser(t *testing.T) {
	groups := make([]string, 1, 4)
	groups[0] = "group1"

	usr := &authuser.DefaultInfo{
		Name:   "alice",
		Groups: groups,
		Extra: map[string][]string{
			"foo": {"x"},
		},
	}

	// Snapshots of exactly what the authenticator must still observe afterwards.
	wantGroupsBacking := append([]string(nil), groups[:cap(groups)]...) // ["group1" "" "" ""]
	wantExtra := map[string][]string{"foo": {"x"}}

	p := withDiscardLoggers(&Proxy{
		config: &Config{
			ExtraUserHeadersClientIPEnabled: true,
			ExtraUserHeaders:                map[string][]string{"foo": {"bar"}},
		},
	})

	handler := p.withImpersonateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(genericapirequest.WithUser(logging.WithRequestID(req.Context(), "test-request-id"), usr))

	handler.ServeHTTP(httptest.NewRecorder(), req)

	// The full backing array of the groups slice must be untouched (catches an
	// in-place append that the len-1 header would otherwise hide).
	if gotBacking := usr.Groups[:cap(usr.Groups)]; !reflect.DeepEqual(gotBacking, wantGroupsBacking) {
		t.Errorf("authenticator groups backing array mutated: got %#v, want %#v", gotBacking, wantGroupsBacking)
	}

	// The extra map must not have gained keys (Remote-Client-IP) nor had its
	// existing value slice extended (foo -> [x bar]).
	if !reflect.DeepEqual(usr.Extra, wantExtra) {
		t.Errorf("authenticator extra map mutated: got %#v, want %#v", usr.Extra, wantExtra)
	}
}

// TestImpersonationSkippedWhenDisabled pins the record for the
// --disable-impersonation path: the request is forwarded with the caller's own
// token and no impersonation headers, which an operator has to be able to see.
func TestImpersonationSkippedWhenDisabled(t *testing.T) {
	p := newTestProxy(t)
	p.config.DisableImpersonation = true

	handler := p.withImpersonateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(logging.NewContext(logging.WithRequestID(req.Context(), "rid-disabled"), p.requestLogger))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := p.logs.Only(t, logging.EventRequestImpersonationSkipped)
	assertRecord(t, rec, logging.EventRequestImpersonationSkipped, logging.ComponentRequest, "rid-disabled")
	if got := rec.String("level"); got != "DEBUG" {
		t.Errorf("level = %q, want DEBUG", got)
	}
	if got := rec.String("skip_reason"); got != skipReasonDisabled {
		t.Errorf("skip_reason = %q, want %q", got, skipReasonDisabled)
	}
	if got := p.logs.ByEvent(logging.EventRequestImpersonationApplied); len(got) != 0 {
		t.Errorf("impersonation was recorded as applied on the disabled path: %s", p.logs.Raw())
	}
}

// TestImpersonationSkippedOnTokenReviewPassthrough pins the other skip path:
// a request the TokenReview fallback admitted carries its own bearer token
// upstream, so impersonation is deliberately never built for it.
func TestImpersonationSkippedOnTokenReviewPassthrough(t *testing.T) {
	p := newTestProxy(t)

	handler := p.withImpersonateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(logging.NewContext(logging.WithRequestID(req.Context(), "rid-passthrough"), p.requestLogger))
	req = reqctx.WithNoImpersonation(req)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := p.logs.Only(t, logging.EventRequestImpersonationSkipped)
	assertRecord(t, rec, logging.EventRequestImpersonationSkipped, logging.ComponentRequest, "rid-passthrough")
	if got := rec.String("skip_reason"); got != skipReasonPassthrough {
		t.Errorf("skip_reason = %q, want %q", got, skipReasonPassthrough)
	}
	if got := p.logs.ByEvent(logging.EventRequestImpersonationApplied); len(got) != 0 {
		t.Errorf("impersonation was recorded as applied on the passthrough path: %s", p.logs.Raw())
	}
}

// TestImpersonationAppliedLogsHeaderNamesOnly pins that the impersonation
// record names the configured extra user headers it applied and never carries
// their values, which are operator-supplied secrets.
func TestImpersonationAppliedLogsHeaderNamesOnly(t *testing.T) {
	p := newTestProxy(t)
	p.config.ExtraUserHeaders = map[string][]string{"tenant": {"acme-secret"}}
	handler := p.withImpersonateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := logging.NewContext(logging.WithRequestID(req.Context(), "rid-3"), p.requestLogger)
	req = req.WithContext(genericapirequest.WithUser(ctx, &authuser.DefaultInfo{Name: "alice"}))
	handler.ServeHTTP(httptest.NewRecorder(), req)
	rec := p.logs.Only(t, logging.EventRequestImpersonationApplied)
	if rec.String("component") != string(logging.ComponentRequest) {
		t.Errorf("component = %q, want %q", rec.String("component"), logging.ComponentRequest)
	}
	if got, want := fmt.Sprint(rec["impersonated_header_names"]),
		"[Impersonate-Extra-tenant Impersonate-Group Impersonate-User]"; got != want {
		t.Errorf("impersonated_header_names = %s, want %s", got, want)
	}
	if !strings.Contains(fmt.Sprint(rec["impersonated_header_names"]), "tenant") || strings.Contains(p.logs.Raw(), "acme-secret") {
		t.Fatalf("%v", p.logs.Raw())
	}
	if got := rec.String("outbound_user"); got != "alice" {
		t.Errorf("outbound_user = %q, want alice", got)
	}
}

// TestOverCapImpersonationRejectedBeforeSubjectAccessReview pins the SAR
// fan-out cap end to end: a request carrying more impersonation header values
// than the configured cap is answered with 431 before any SubjectAccessReview
// is submitted, and never reaches the inner handler.
func TestOverCapImpersonationRejectedBeforeSubjectAccessReview(t *testing.T) {
	p := newTestProxy(t)

	reviewer := &countingReviewer{FakeReviewer: fakesubjectaccessreview.New(nil)}
	sar, err := subjectaccessreview.New(reviewer, subjectaccessreview.Config{Timeout: subjectaccessreview.DefaultTimeout, AllowCacheTTL: 0, DenyCacheTTL: 0, MaxHeaderValues: 2}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("creating subject access reviewer: %s", err)
	}
	p.subjectAccessReviewer = sar

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		oidcAnswer(&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: []string{"devs"}},
		}, true, nil))

	var served bool
	handler := p.withHandlers(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		served = true
	}))

	// Three impersonation header values against a cap of two.
	req := reservedIdentityRequest(t, map[string]string{
		"Impersonate-User": "jjackson",
	})
	req.Header.Add("Impersonate-Group", "group3")
	req.Header.Add("Impersonate-Group", "group4")

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if served {
		t.Error("inner handler was reached for an over-cap impersonation request")
	}
	if got, want := rw.Result().StatusCode, http.StatusRequestHeaderFieldsTooLarge; got != want {
		t.Errorf("unexpected response code, exp=%d got=%d", want, got)
	}
	if got := rw.Body.String(); !strings.Contains(got, "too many impersonation header values") {
		t.Errorf("response body does not explain the rejection: %q", got)
	}
	if got := reviewer.reviews.Load(); got != 0 {
		t.Errorf("SubjectAccessReviews were submitted for an over-cap request, exp=0 got=%d", got)
	}

	p.ctrl.Finish()
}
