// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview"
	fakesubjectaccessreview "github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview/fake"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

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
	p := newTestProxy(t, withConfig(Config{AllowedReservedGroups: []string{"system:masters"}}))

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

// TestReservedIdentityRejectedBeforeSubjectAccessReview is the ordering
// property that makes the guard meaningful. ResolveImpersonation
// builds its SubjectAccessReview with the requester's own groups, so a forged
// system: group would otherwise feed the authorization decision — not merely
// the impersonation headers. No review may be submitted at all.
func TestReservedIdentityRejectedBeforeSubjectAccessReview(t *testing.T) {
	reviewer := &countingReviewer{FakeReviewer: fakesubjectaccessreview.New(nil)}
	sar := subjectaccessreview.New(reviewer, subjectaccessreview.Config{MaxHeaderValues: subjectaccessreview.DefaultMaxHeaderValues}, slog.New(slog.DiscardHandler))
	p := newTestProxy(t, withSubjectAccessReviewer(sar))

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		oidcAnswer(&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: []string{"system:masters"}},
		}, true, nil))

	var served bool
	handler := p.withFilterChain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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

func TestReservedIdentityEmitsAnomalyAndDeniedAccess(t *testing.T) {
	p := newTestProxy(t)
	reservedIdentityUser(p, []string{"system:masters"}, 1)
	rw := httptest.NewRecorder()
	req := reservedIdentityRequest(t, nil)
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
		p.withAuthenticateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)
	}
	if n := len(p.logs.ByEvent(logging.EventRequestAccessDecided)); n != 10 {
		t.Fatalf("access records = %d, want 10 (never sampled)", n)
	}
	if n := len(p.logs.ByEvent(logging.EventRequestAnomalyDetected)); n != 3 {
		t.Fatalf("anomaly records = %d, want burst 3", n)
	}
}
