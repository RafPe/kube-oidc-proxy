// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/mock/gomock"
	azv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"

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
	req = req.WithContext(genericapirequest.WithUser(req.Context(), usr))

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

// TestWithAuthenticateRequestLogsValidationFailureAtV2 asserts that a token
// that was present and failed OIDC validation is reported at a verbosity
// operators actually run at, with the resolved remote address. Routing is
// unchanged: the request still falls through to the token-review path.
func TestWithAuthenticateRequestLogsValidationFailureAtV2(t *testing.T) {
	buf := captureKlogAtV2(t)

	p := newTestProxy(t)

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
		nil, false, errors.New("oidc: token is expired"))

	handler := p.withAuthenticateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("inner handler was reached for a token that failed validation")
	}))

	rw := httptest.NewRecorder()
	req := reservedIdentityRequest(t, nil)
	req.RemoteAddr = "8.8.8.8:1234"
	handler.ServeHTTP(rw, req)

	// Routing is unchanged: token review is disabled here, so the request is
	// still answered as unauthorized rather than being rejected outright.
	if got, want := rw.Result().StatusCode, http.StatusUnauthorized; got != want {
		t.Errorf("unexpected response code, exp=%d got=%d", want, got)
	}

	klog.Flush()
	logged := buf.String()
	if !strings.Contains(logged, "oidc: token is expired") {
		t.Errorf("validation failure was not logged at V(2), got: %q", logged)
	}
	if !strings.Contains(logged, "8.8.8.8") {
		t.Errorf("validation failure log does not name the remote address, got: %q", logged)
	}

	p.ctrl.Finish()
}

// captureKlogAtV2 redirects klog to a buffer at verbosity 2 for the duration of
// the test. klog's verbosity and output are process-global, so the cleanup
// restores both — including the output writer, which would otherwise leave
// later klog calls in this package writing into a dead buffer.
func captureKlogAtV2(t *testing.T) *bytes.Buffer {
	t.Helper()

	var fs flag.FlagSet
	klog.InitFlags(&fs)
	previousVerbosity := fs.Lookup("v").Value.String()
	if err := fs.Set("v", "2"); err != nil {
		t.Fatalf("setting klog verbosity: %s", err)
	}

	buf := new(bytes.Buffer)
	klog.LogToStderr(false)
	klog.SetOutput(buf)

	t.Cleanup(func() {
		klog.Flush()
		if err := fs.Set("v", previousVerbosity); err != nil {
			t.Errorf("restoring klog verbosity: %s", err)
		}
		klog.SetOutput(os.Stderr)
		klog.LogToStderr(true)
	})

	return buf
}

// TestCheckReservedIdentity covers the username/group asymmetry. Username has
// no exception at all; groups permit exactly AllAuthenticated because the proxy
// appends it to every request itself.
func TestCheckReservedIdentity(t *testing.T) {
	tests := map[string]struct {
		info    authuser.Info
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
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := checkReservedIdentity(test.info)

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
// authenticator wired by newTestProxy is primed to answer.
func reservedIdentityRequest(t *testing.T, extraHeaders map[string]string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
	req.Header.Set("Authorization", "bearer fake-token")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	return req
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

func TestWithAuthenticateRequestAllowsReservedIdentityWhenOptedIn(t *testing.T) {
	p := newTestProxy(t)
	p.config.AllowReservedIdentityClaims = true

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
		t.Error("inner handler was not reached with --allow-reserved-identity-claims set")
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

// TestReservedIdentityRejectedBeforeSubjectAccessReview is the ordering
// property that makes the guard meaningful. CheckAuthorizedForImpersonation
// builds its SubjectAccessReview with the requester's own groups, so a forged
// system: group would otherwise feed the authorization decision — not merely
// the impersonation headers. No review may be submitted at all.
func TestReservedIdentityRejectedBeforeSubjectAccessReview(t *testing.T) {
	p := newTestProxy(t)

	reviewer := &countingReviewer{FakeReviewer: fakesubjectaccessreview.New(nil)}
	sar, err := subjectaccessreview.New(reviewer, subjectaccessreview.DefaultTimeout)
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
