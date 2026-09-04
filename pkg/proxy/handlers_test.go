// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"go.uber.org/mock/gomock"
	azv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	proxycontext "github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
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

	p := &Proxy{
		config: &Config{
			ExtraUserHeadersClientIPEnabled: true,
			ExtraUserHeaders:                map[string][]string{"foo": {"bar"}},
		},
	}

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

// assertRecord checks the three fields every first-party record is queried by:
// the event type it claims, the component that owns it, and the correlation id
// that ties it back to a request.
func assertRecord(t *testing.T, rec logtest.Record, event logging.EventType, component logging.Component, requestID string) {
	t.Helper()
	if got := rec.String("event_type"); got != string(event) {
		t.Errorf("event_type = %q, want %q", got, event)
	}
	if got := rec.String("component"); got != string(component) {
		t.Errorf("component = %q, want %q", got, component)
	}
	if got := rec.String("request_id"); got != requestID {
		t.Errorf("request_id = %q, want %q", got, requestID)
	}
}

// TestOIDCSuccessEmitsAuthnOIDCSucceeded pins the record the OIDC path writes
// when it accepts a token, including the name of the issuer that accepted it:
// with several issuers configured, a record that cannot say which one answered
// cannot answer the question the event exists for.
func TestOIDCSuccessEmitsAuthnOIDCSucceeded(t *testing.T) {
	p := newTestProxy(t)
	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		oidcAnswer(&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: []string{"devs"}},
		}, true, nil))

	var served bool
	handler := p.withAuthenticateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		served = true
	}))

	req := reservedIdentityRequest(t, nil)
	req = req.WithContext(logging.NewContext(req.Context(), p.logger))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !served {
		t.Fatal("inner handler was not reached for an accepted token")
	}

	rec := p.logs.Only(t, logging.EventAuthnOIDCSucceeded)
	assertRecord(t, rec, logging.EventAuthnOIDCSucceeded, logging.ComponentOIDC, "test-request-id")
	if got := rec.String("level"); got != "DEBUG" {
		t.Errorf("level = %q, want DEBUG", got)
	}
	if got := rec.String("issuer_name"); got != testIssuerName {
		t.Errorf("issuer_name = %q, want %q", got, testIssuerName)
	}

	p.ctrl.Finish()
}

// TestImpersonationSkippedWhenDisabled pins the record for the
// --disable-impersonation path: the request is forwarded with the caller's own
// token and no impersonation headers, which an operator has to be able to see.
func TestImpersonationSkippedWhenDisabled(t *testing.T) {
	p := newTestProxy(t)
	p.config.DisableImpersonation = true

	handler := p.withImpersonateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(logging.NewContext(logging.WithRequestID(req.Context(), "rid-disabled"), p.logger))
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
	req = req.WithContext(logging.NewContext(logging.WithRequestID(req.Context(), "rid-passthrough"), p.logger))
	req = proxycontext.WithNoImpersonation(req)
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

// TestTokenReviewDependencyFailureIsError separates the two ways a TokenReview
// can fail to admit a request. An API server that could not answer is an
// operator-visible dependency failure carrying the error text; it is not a
// verdict on the credential, so it must not be recorded as a completed review.
func TestTokenReviewDependencyFailureIsError(t *testing.T) {
	p := newTestProxy(t)
	p.fakeReviewer.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
		nil, false, errors.New("apiserver unreachable"))

	req := reservedIdentityRequest(t, nil)
	req = req.WithContext(logging.NewContext(req.Context(), p.logger))

	if ok := p.reviewToken(httptest.NewRecorder(), req); ok {
		t.Fatal("a reviewer error passed the request through; the path must fail closed")
	}

	rec := p.logs.Only(t, logging.EventAuthnTokenReviewFailed)
	assertRecord(t, rec, logging.EventAuthnTokenReviewFailed, logging.ComponentTokenReview, "test-request-id")
	if got := rec.String("level"); got != "ERROR" {
		t.Errorf("level = %q, want ERROR", got)
	}
	if got := rec.String("reason"); got != reasonAuthenticationDependencyError {
		t.Errorf("reason = %q, want %q", got, reasonAuthenticationDependencyError)
	}
	if got := rec.String("error_message"); got != "apiserver unreachable" {
		t.Errorf("error_message = %q, want %q", got, "apiserver unreachable")
	}
	if got := p.logs.ByEvent(logging.EventAuthnTokenReviewCompleted); len(got) != 0 {
		t.Errorf("an unanswerable TokenReview was recorded as completed: %s", p.logs.Raw())
	}

	p.ctrl.Finish()
}

// TestClientCancellationEmitsUpstreamRequestCanceled pins the one refusal that
// writes no response at all: the client is already gone. It is routine, so the
// record is DEBUG, but the access decision is still written.
func TestClientCancellationEmitsUpstreamRequestCanceled(t *testing.T) {
	p := newTestProxy(t)

	req := reservedIdentityRequest(t, nil)
	rw := httptest.NewRecorder()
	p.handleError(rw, req, context.Canceled)

	rec := p.logs.Only(t, logging.EventUpstreamRequestCanceled)
	assertRecord(t, rec, logging.EventUpstreamRequestCanceled, logging.ComponentUpstream, "test-request-id")
	if got := rec.String("level"); got != "DEBUG" {
		t.Errorf("level = %q, want DEBUG", got)
	}
	if got := rec.String("reason"); got != reasonClientCanceled {
		t.Errorf("reason = %q, want %q", got, reasonClientCanceled)
	}
	assertDeniedReason(t, p.logs, reasonClientCanceled)
}

// TestOIDCFailureEmitsAuthnOIDCFailed asserts that a token that was present
// and failed OIDC validation produces the structured failure event, carrying
// the request id from the context and the resolved client IP -- never the raw
// peer address with its port. Routing is unchanged: the request still falls
// through to the token-review path.
func TestOIDCFailureEmitsAuthnOIDCFailed(t *testing.T) {
	p := newTestProxy(t)
	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(nil, false, errors.New("oidc: token is expired"))
	handler := p.withAuthenticateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("reached inner") }))
	req := reservedIdentityRequest(t, nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req = proxycontext.WithRequestID(req, "rid-1")
	req = req.WithContext(logging.NewContext(logging.WithRequestID(req.Context(), "rid-1"), p.logger))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := p.logs.Only(t, logging.EventAuthnOIDCFailed)
	if rec.String("component") != string(logging.ComponentOIDC) {
		t.Errorf("component = %q, want %q", rec.String("component"), logging.ComponentOIDC)
	}
	if rec.String("request_id") != "rid-1" || rec.String("src_ip") != "8.8.8.8" || rec.String("reason") != "unauthorized" {
		t.Fatalf("%v", rec)
	}
	if strings.Contains(p.logs.Raw(), "8.8.8.8:1234") {
		t.Fatal("raw peer address with port logged")
	}
}

// TestMissingBearerOnTokenReviewIsDebug pins the level of the token-review
// path's "no credential presented" record: it is routine traffic, not an
// operator-visible condition.
func TestMissingBearerOnTokenReviewIsDebug(t *testing.T) {
	p := newTestProxy(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil) // no Authorization
	req = req.WithContext(logging.NewContext(logging.WithRequestID(req.Context(), "rid-2"), p.logger))
	p.reviewToken(httptest.NewRecorder(), req)
	rec := p.logs.Only(t, logging.EventAuthnTokenMissing)
	if rec.String("level") != "DEBUG" {
		t.Fatalf("level = %s", rec.String("level"))
	}
	if rec.String("component") != string(logging.ComponentTokenReview) {
		t.Errorf("component = %q, want %q", rec.String("component"), logging.ComponentTokenReview)
	}
}

// TestRejectedTokenReviewIsCompletedNotAuthenticated pins that a TokenReview
// which answered "not authenticated" is a completed review carrying the
// outcome, not a failure: only an unreachable or erroring API server is a
// failure.
func TestRejectedTokenReviewIsCompletedNotAuthenticated(t *testing.T) {
	p := newTestProxy(t)
	p.fakeReviewer.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(nil, false, nil)
	req := reservedIdentityRequest(t, nil)
	req = req.WithContext(logging.NewContext(req.Context(), p.logger))
	p.reviewToken(httptest.NewRecorder(), req)
	rec := p.logs.Only(t, logging.EventAuthnTokenReviewCompleted)
	if v := rec["authenticated"]; v != false {
		t.Fatalf("authenticated = %v", v)
	}
	if rec.String("component") != string(logging.ComponentTokenReview) {
		t.Errorf("component = %q, want %q", rec.String("component"), logging.ComponentTokenReview)
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
	ctx := logging.NewContext(logging.WithRequestID(req.Context(), "rid-3"), p.logger)
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

// TestCheckReservedIdentity covers the username/group asymmetry. Username has
// no exception at all; groups permit exactly AllAuthenticated because the proxy
// appends it to every request itself.
func TestCheckReservedIdentity(t *testing.T) {
	tests := map[string]struct {
		info    authuser.Info
		allowed sets.Set[string]
		wantErr bool
	}{
		"system:masters group": {
			info:    &authuser.DefaultInfo{Name: "alice", Groups: []string{"system:masters"}},
			wantErr: true,
		},
		"system:authenticated group": {
			info:    &authuser.DefaultInfo{Name: "alice", Groups: []string{authuser.AllAuthenticated}},
			wantErr: false,
		},
		"system:unauthenticated group": {
			info:    &authuser.DefaultInfo{Name: "alice", Groups: []string{"system:unauthenticated"}},
			wantErr: true,
		},
		"system: username": {
			info:    &authuser.DefaultInfo{Name: "system:masters"},
			wantErr: true,
		},
		// The group-side exception must NOT leak to the username: a reserved
		// username can be granted rights by an RBAC binding naming it as a User.
		"system:authenticated username": {
			info:    &authuser.DefaultInfo{Name: authuser.AllAuthenticated},
			wantErr: true,
		},
		"system:serviceaccount username": {
			info:    &authuser.DefaultInfo{Name: "system:serviceaccount:kube-system:default"},
			wantErr: true,
		},
		"ordinary identity": {
			info:    &authuser.DefaultInfo{Name: "alice", Groups: []string{"dev"}},
			wantErr: false,
		},
		"lookalike identity": {
			info:    &authuser.DefaultInfo{Name: "system-admin", Groups: []string{"systemd:ops"}},
			wantErr: false,
		},
		"allowlisted group is permitted": {
			info:    &authuser.DefaultInfo{Name: "alice", Groups: []string{"system:monitoring"}},
			allowed: sets.New("system:monitoring"),
			wantErr: false,
		},
		"allowlist does not permit other reserved groups": {
			info:    &authuser.DefaultInfo{Name: "alice", Groups: []string{"system:masters"}},
			allowed: sets.New("system:monitoring"),
			wantErr: true,
		},
		"allowlist does not permit a reserved username": {
			info:    &authuser.DefaultInfo{Name: "system:monitoring", Groups: []string{"dev"}},
			allowed: sets.New("system:monitoring"),
			wantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := checkReservedIdentity(test.info, test.allowed)

			if test.wantErr {
				if err == nil {
					t.Fatalf("checkReservedIdentity(%#v) = nil, want an error", test.info)
				}
				if !errors.Is(err, errReservedIdentity) {
					t.Errorf("checkReservedIdentity(%#v) error = %v, want errReservedIdentity", test.info, err)
				}
				return
			}

			if err != nil {
				t.Errorf("checkReservedIdentity(%#v) = %v, want nil", test.info, err)
			}
		})
	}
}

// reservedIdentityRequest builds a bearer-token request that the fake
// authenticator wired by newTestProxy is primed to answer. It carries the
// correlation id the request-id filter mints in production, which every access
// record is required to report.
func reservedIdentityRequest(t *testing.T, extraHeaders map[string]string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
	req.Header.Set("Authorization", "bearer fake-token")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	return withTestRequestID(req)
}

func TestWithAuthenticateRequestRejectsReservedIdentity(t *testing.T) {
	p := newTestProxy(t)

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		oidcAnswer(&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: []string{"system:masters"}},
		}, true, nil))

	var served bool
	handler := p.withAuthenticateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		served = true
	}))

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, reservedIdentityRequest(t, nil))

	if served {
		t.Error("inner handler was reached for a reserved identity")
	}
	if got, want := rw.Result().StatusCode, http.StatusForbidden; got != want {
		t.Errorf("unexpected response code, exp=%d got=%d", want, got)
	}
	if got := rw.Body.String(); !strings.Contains(got, "system:") {
		t.Errorf("response body does not explain the rejection: %q", got)
	}

	p.ctrl.Finish()
}

func TestWithAuthenticateRequestAllowsAllowlistedReservedGroup(t *testing.T) {
	p := newTestProxy(t)
	p.allowedReservedGroups = sets.New("system:masters")

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		oidcAnswer(&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: []string{"system:masters"}},
		}, true, nil))

	var served bool
	handler := p.withAuthenticateRequest(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		served = true

		user, ok := genericapirequest.UserFrom(req.Context())
		if !ok {
			t.Error("no user in request context")
			return
		}
		if user.GetName() != "alice" {
			t.Errorf("unexpected user in request context, exp=alice got=%q", user.GetName())
		}
	}))

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, reservedIdentityRequest(t, nil))

	if !served {
		t.Error("inner handler was not reached with the reserved group allowlisted")
	}
	if got, want := rw.Result().StatusCode, http.StatusOK; got != want {
		t.Errorf("unexpected response code, exp=%d got=%d", want, got)
	}

	p.ctrl.Finish()
}

// countingReviewer records how many SubjectAccessReviews were submitted while
// delegating the decision itself to the shared fake.
type countingReviewer struct {
	*fakesubjectaccessreview.FakeReviewer

	reviews atomic.Int64
}

func (c *countingReviewer) Create(ctx context.Context, req *azv1.SubjectAccessReview, co metav1.CreateOptions) (*azv1.SubjectAccessReview, error) {
	c.reviews.Add(1)
	return c.FakeReviewer.Create(ctx, req, co)
}

// TestOverCapImpersonationRejectedBeforeSubjectAccessReview pins the SAR
// fan-out cap end to end: a request carrying more impersonation header values
// than the configured cap is answered with 431 before any SubjectAccessReview
// is submitted, and never reaches the inner handler.
func TestOverCapImpersonationRejectedBeforeSubjectAccessReview(t *testing.T) {
	p := newTestProxy(t)

	reviewer := &countingReviewer{FakeReviewer: fakesubjectaccessreview.New(nil)}
	sar, err := subjectaccessreview.New(reviewer, subjectaccessreview.DefaultTimeout, 0, 0, 2, slog.New(slog.DiscardHandler))
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

// TestReservedIdentityRejectedBeforeSubjectAccessReview is the ordering
// property that makes the guard meaningful. CheckAuthorizedForImpersonation
// builds its SubjectAccessReview with the requester's own groups, so a forged
// system: group would otherwise feed the authorization decision — not merely
// the impersonation headers. No review may be submitted at all.
func TestReservedIdentityRejectedBeforeSubjectAccessReview(t *testing.T) {
	p := newTestProxy(t)

	reviewer := &countingReviewer{FakeReviewer: fakesubjectaccessreview.New(nil)}
	sar, err := subjectaccessreview.New(reviewer, subjectaccessreview.DefaultTimeout, 0, 0, subjectaccessreview.DefaultMaxHeaderValues, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("creating subject access reviewer: %s", err)
	}
	p.subjectAccessReviewer = sar

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		oidcAnswer(&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: []string{"system:masters"}},
		}, true, nil))

	var served bool
	handler := p.withHandlers(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		served = true
	}))

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, reservedIdentityRequest(t, map[string]string{
		"Impersonate-User": "jjackson",
	}))

	if served {
		t.Error("inner handler was reached for a reserved identity")
	}
	if got, want := rw.Result().StatusCode, http.StatusForbidden; got != want {
		t.Errorf("unexpected response code, exp=%d got=%d", want, got)
	}
	if got := rw.Body.String(); !strings.Contains(got, "system:") {
		t.Errorf("response body does not explain the rejection: %q", got)
	}
	if got := reviewer.reviews.Load(); got != 0 {
		t.Errorf("SubjectAccessReviews were submitted for a reserved identity, exp=0 got=%d", got)
	}

	p.ctrl.Finish()
}

// reservedIdentityUser primes the fake authenticator to answer with an
// identity carrying a reserved group, so a request built by
// reservedIdentityRequest is refused by checkReservedIdentity.
func reservedIdentityUser(p *fakeProxy, groups []string, times int) {
	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		oidcAnswer(&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: groups},
		}, true, nil)).Times(times)
}

func TestUntrustedForwardedHeadersDroppedIsWarn(t *testing.T) {
	p := newTestProxy(t)
	h := p.withSanitizedForwardHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-Ip", "1.2.3.4")
	req = withTestRequestID(req)
	req = req.WithContext(logging.NewContext(req.Context(), p.logger))
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
	req = req.WithContext(logging.NewContext(req.Context(), p.logger))
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
	p := newTestProxy(t)
	p.trustedProxies = mustCIDRs(t, "10.0.0.0/8")
	proxycontext.SetTrustedProxies(p.trustedProxies)
	t.Cleanup(func() { proxycontext.SetTrustedProxies(nil) })
	h := p.withSanitizedForwardHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.7:1"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.9")
	req = withTestRequestID(req)
	req = req.WithContext(logging.NewContext(req.Context(), p.logger))
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
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.7:1"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.9")
	req = withTestRequestID(req)
	req = req.WithContext(logging.NewContext(req.Context(), logging.ForComponent(quiet, logging.ComponentRequest)))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if n := len(quietLogs.ByEvent(logging.EventRequestHeadersRewritten)); n != 0 {
		t.Fatalf("rewritten records at -v=0 = %d, want 0: %s", n, quietLogs.Raw())
	}
}

func TestReservedIdentityEmitsAnomalyAndDeniedAccess(t *testing.T) {
	p := newTestProxy(t)
	reservedIdentityUser(p, []string{"system:masters"}, 1)
	rw := httptest.NewRecorder()
	req := reservedIdentityRequest(t, nil)
	req = req.WithContext(logging.NewContext(req.Context(), p.logger))
	p.withAuthenticateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rw, req)
	if p.logs.Only(t, logging.EventRequestAnomalyDetected).String("reason") != "reserved_identity" {
		t.Fatal("anomaly not recorded")
	}
	if p.logs.Only(t, logging.EventRequestAccessDecided).String("reason") != "reserved_identity" {
		t.Fatal("access record missing reason")
	}
}

func TestAnomalyIsRateLimitedButAccessRecordIsNot(t *testing.T) {
	p := newTestProxy(t) // limiter burst 3 in tests
	reservedIdentityUser(p, []string{"system:masters"}, 10)
	for i := 0; i < 10; i++ {
		req := reservedIdentityRequest(t, nil)
		req = req.WithContext(logging.NewContext(req.Context(), p.logger))
		p.withAuthenticateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)
	}
	if n := len(p.logs.ByEvent(logging.EventRequestAccessDecided)); n != 10 {
		t.Fatalf("access records = %d, want 10 (never sampled)", n)
	}
	if n := len(p.logs.ByEvent(logging.EventRequestAnomalyDetected)); n != 3 {
		t.Fatalf("anomaly records = %d, want burst 3", n)
	}
}

// TestFlushWarnLimiterSummarisesOnShutdown covers the shutdown half of the
// flush loop: a burst suppressed just before the proxy stops is still
// accounted for, rather than lost with the goroutine.
func TestFlushWarnLimiterSummarisesOnShutdown(t *testing.T) {
	p := newTestProxy(t)
	for i := 0; i < 10; i++ {
		p.warnLimiter.Allow(reasonReservedIdentity)
	}

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.flushWarnLimiter(stopCh)
	}()
	close(stopCh)
	<-done

	rec := p.logs.Only(t, logging.EventLogWarningSuppressed)
	if n, _ := rec.Int("suppressed_count"); n != 7 {
		t.Fatalf("suppressed_count = %d, want 7 (10 offered, burst of 3 allowed)", n)
	}
	if rec.String("warning_reason") != reasonReservedIdentity {
		t.Fatalf("%v", rec)
	}
}

// TestErrorHandlerClassifiesUpstreamTransportErrors pins the upstream branch:
// a transport failure on the hop to the API server is answered 502, carries a
// classified termination on its own upstream record, and never writes a second
// access decision -- RoundTrip already recorded the admission.
func TestErrorHandlerClassifiesUpstreamTransportErrors(t *testing.T) {
	cases := map[string]struct {
		err  error
		term string
	}{
		"timeout": {err: &net.OpError{Op: "dial", Err: &timeoutErr{}}, term: "upstream_timeout"},
		"reset":   {err: &net.OpError{Op: "read", Err: syscall.ECONNRESET}, term: "upstream_reset"},
		"eof":     {err: io.EOF, term: "upstream_reset"},
		// A TLS failure is an upstream failure the transport could not classify
		// any further: the hop happened, the peer was simply not trusted.
		"other": {err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, term: "proxy_error"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)
			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req = withTestRequestID(req)
			req = req.WithContext(logging.NewContext(req.Context(), p.logger))
			p.handleError(rw, req, c.err)
			if rw.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502", rw.Code)
			}
			up := p.logs.Only(t, logging.EventUpstreamRequestFailed)
			if up.String("termination") != c.term || up.String("reason") != reasonUpstreamError {
				t.Fatalf("%v", up)
			}
			if got := p.logs.ByEvent(logging.EventRequestAccessDecided); len(got) != 0 {
				t.Fatalf("an upstream failure wrote %d access records: %s", len(got), p.logs.Raw())
			}
		})
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
