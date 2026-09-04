// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/mock/gomock"
	azv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
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

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
		&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: []string{"system:masters"}},
		}, true, nil)

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

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
		&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: []string{"system:masters"}},
		}, true, nil)

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

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
		&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: []string{"devs"}},
		}, true, nil)

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

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
		&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: []string{"system:masters"}},
		}, true, nil)

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
