// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"go.uber.org/mock/gomock"
	azv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
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

	p := newTestProxy(t, withConfig(Config{
		ExtraUserHeadersClientIPEnabled: true,
		ExtraUserHeaders:                map[string][]string{"foo": {"bar"}},
	}))

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
	p := newTestProxy(t, withConfig(Config{DisableImpersonation: true}))

	handler := p.withImpersonateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(logging.WithRequestID(req.Context(), "rid-disabled"))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := p.logs.Only(t, logging.EventRequestImpersonationSkipped)
	assertRecord(t, rec, logging.EventRequestImpersonationSkipped, logging.ComponentRequest, "rid-disabled")
	if got := rec.String("level"); got != "DEBUG" {
		t.Errorf("level = %q, want DEBUG", got)
	}
	if got := rec.String("skip_reason"); got != string(reqctx.ForwardDisabled) {
		t.Errorf("skip_reason = %q, want %q", got, reqctx.ForwardDisabled)
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
	req = req.WithContext(logging.WithRequestID(req.Context(), "rid-passthrough"))
	// What withTokenReview leaves on a request it admitted.
	req = reqctx.WithImpersonation(req, &reqctx.ImpersonationRecord{Mode: reqctx.ForwardPassthrough})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := p.logs.Only(t, logging.EventRequestImpersonationSkipped)
	assertRecord(t, rec, logging.EventRequestImpersonationSkipped, logging.ComponentRequest, "rid-passthrough")
	if got := rec.String("skip_reason"); got != string(reqctx.ForwardPassthrough) {
		t.Errorf("skip_reason = %q, want %q", got, reqctx.ForwardPassthrough)
	}
	if got := p.logs.ByEvent(logging.EventRequestImpersonationApplied); len(got) != 0 {
		t.Errorf("impersonation was recorded as applied on the passthrough path: %s", p.logs.Raw())
	}
}

// TestImpersonationAppliedLogsHeaderNamesOnly pins that the impersonation
// record names the configured extra user headers it applied and never carries
// their values, which are operator-supplied secrets.
func TestImpersonationAppliedLogsHeaderNamesOnly(t *testing.T) {
	p := newTestProxy(t, withConfig(Config{ExtraUserHeaders: map[string][]string{"tenant": {"acme-secret"}}}))
	handler := p.withImpersonateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := logging.WithRequestID(req.Context(), "rid-3")
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
	reviewer := &countingReviewer{FakeReviewer: fakesubjectaccessreview.New(nil)}
	sar := subjectaccessreview.New(reviewer, subjectaccessreview.Config{MaxHeaderValues: 2}, slog.New(slog.DiscardHandler))
	p := newTestProxy(t, withSubjectAccessReviewer(sar))

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		oidcAnswer(&authenticator.Response{
			User: &authuser.DefaultInfo{Name: "alice", Groups: []string{"devs"}},
		}, true, nil))

	var served bool
	handler := p.withFilterChain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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

// specRecordingReviewer records the requester groups of every review it is
// asked, and allows them all.
type specRecordingReviewer struct {
	*fakesubjectaccessreview.FakeReviewer

	mu     sync.Mutex
	groups [][]string
}

func (r *specRecordingReviewer) Create(_ context.Context, req *azv1.SubjectAccessReview, _ metav1.CreateOptions) (*azv1.SubjectAccessReview, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.groups = append(r.groups, slices.Clone(req.Spec.Groups))
	req.Status = azv1.SubjectAccessReviewStatus{Allowed: true}
	return req, nil
}

// TestSubjectAccessReviewRequesterIsAuthenticated pins that the proxy asks
// about the requester the way kube-apiserver authorizes it: with
// system:authenticated among its groups, exactly once, whether or not the
// token's own groups carried it. An impersonate grant bound to that group
// works against the API server directly, so it must work through the proxy.
// The identity the authenticator returned is not touched.
func TestSubjectAccessReviewRequesterIsAuthenticated(t *testing.T) {
	for name, groups := range map[string][]string{
		"token groups without it": {"devs"},
		"token groups with it":    {"devs", authuser.AllAuthenticated},
		"no token groups":         nil,
	} {
		t.Run(name, func(t *testing.T) {
			reviewer := &specRecordingReviewer{FakeReviewer: fakesubjectaccessreview.New(nil)}
			sar := subjectaccessreview.New(reviewer, subjectaccessreview.Config{MaxHeaderValues: subjectaccessreview.DefaultMaxHeaderValues}, slog.New(slog.DiscardHandler))
			p := newTestProxy(t, withSubjectAccessReviewer(sar))

			inbound := &authuser.DefaultInfo{Name: "alice", Groups: slices.Clone(groups)}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Impersonate-User", "bob")
			req = req.WithContext(genericapirequest.WithUser(logging.WithRequestID(req.Context(), "test-request-id"), inbound))

			var served bool
			p.withImpersonateRequest(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true })).
				ServeHTTP(httptest.NewRecorder(), req)
			if !served {
				t.Fatalf("an allowed impersonation was not served: %s", p.logs.Raw())
			}

			if len(reviewer.groups) != 1 {
				t.Fatalf("reviews = %d, want 1", len(reviewer.groups))
			}
			got := reviewer.groups[0]
			if n := slices.Index(got, authuser.AllAuthenticated); n < 0 || slices.Contains(got[n+1:], authuser.AllAuthenticated) {
				t.Errorf("requester groups = %q, want %s exactly once", got, authuser.AllAuthenticated)
			}
			if !slices.Contains(got, "devs") && len(groups) > 0 {
				t.Errorf("requester groups = %q, lost the token's own groups", got)
			}
			if !reflect.DeepEqual(inbound.Groups, groups) {
				t.Errorf("the authenticator's identity was mutated: groups = %q, want %q", inbound.Groups, groups)
			}
		})
	}
}

// attributeRecordingReviewer allows every review and records what each one
// asked about, so a test can check the client's request was still authorized.
type attributeRecordingReviewer struct {
	*fakesubjectaccessreview.FakeReviewer

	mu    sync.Mutex
	asked []azv1.ResourceAttributes
}

func (r *attributeRecordingReviewer) Create(_ context.Context, req *azv1.SubjectAccessReview, _ metav1.CreateOptions) (*azv1.SubjectAccessReview, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, *req.Spec.ResourceAttributes)
	req.Status = azv1.SubjectAccessReviewStatus{Allowed: true}
	return req, nil
}

// TestClientCannotAssertOriginalUserExtras pins that every
// originaluser.jetstack.io-* key on the forwarded request is the proxy's own,
// derived from the identity it authenticated. A client that impersonates one
// of those keys is still authorized for exactly what it asked -- the
// SubjectAccessReview runs -- but its value never travels: the key carries
// the inbound identity's value, or is absent when the inbound has none.
// Before this, a client allowed to impersonate the key forwarded its own
// value wherever the inbound identity had none, naming someone else as the
// original user in the API server's audit log.
func TestClientCannotAssertOriginalUserExtras(t *testing.T) {
	const spoof = "mallory"

	full := &authuser.DefaultInfo{Name: "alice", UID: "alice-uid", Groups: []string{"devs"},
		Extra: map[string][]string{"acme.io/team": {"platform"}}}
	bare := &authuser.DefaultInfo{Name: "alice"}

	tests := map[string]struct {
		key     string
		inbound *authuser.DefaultInfo
		want    []string // nil: the key must be absent
	}{
		"user":                         {ExtraKeyOriginalUser, full, []string{"alice"}},
		"user, bare inbound":           {ExtraKeyOriginalUser, bare, []string{"alice"}},
		"groups":                       {ExtraKeyOriginalGroups, full, []string{"devs"}},
		"groups, inbound has no":       {ExtraKeyOriginalGroups, bare, nil},
		"uid":                          {ExtraKeyOriginalUID, full, []string{"alice-uid"}},
		"uid, inbound has no":          {ExtraKeyOriginalUID, bare, nil},
		"extra":                        {ExtraKeyOriginalExtra, full, []string{`{"acme.io/team":["platform"]}`}},
		"extra, inbound has no":        {ExtraKeyOriginalExtra, bare, nil},
		"unknown key under the prefix": {originalUserExtraPrefix + "anything", full, nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			imp, reviewer := impersonateBob(t, Config{}, tc.inbound, map[string]string{tc.key: spoof})
			assertExtraAuthorized(t, reviewer, tc.key, spoof)

			got, present := imp.Outbound.Extra[tc.key]
			switch {
			case tc.want == nil && present:
				t.Errorf("extra %s = %q, want absent", tc.key, got)
			case tc.want != nil && !reflect.DeepEqual(got, tc.want):
				t.Errorf("extra %s = %q, want %q", tc.key, got, tc.want)
			}
			for k, vs := range imp.Outbound.Extra {
				if slices.Contains(vs, spoof) {
					t.Errorf("the client's value reached the forwarded extra %s = %q", k, vs)
				}
			}
		})
	}
}

// TestClientCannotAssertProxyWrittenExtras extends the same rule to every
// other key the proxy writes: the client-IP key while it is enabled, and the
// operator's configured extras. Keys are compared ignoring case, because the
// API server receives each as a canonicalised Impersonate-Extra- header, where
// "remote-client-ip" and "Remote-Client-IP" are one header. A key the proxy
// does not write remains the client's.
func TestClientCannotAssertProxyWrittenExtras(t *testing.T) {
	const spoof = "6.6.6.6"
	inbound := &authuser.DefaultInfo{Name: "alice"}

	tests := map[string]struct {
		cfg       Config
		clientKey string
		wantKey   string
		want      []string
	}{
		"client IP enabled": {
			cfg:       Config{ExtraUserHeadersClientIPEnabled: true},
			clientKey: "Remote-Client-IP", wantKey: ExtraKeyClientIP, want: []string{"192.0.2.1"},
		},
		"client IP disabled leaves the key to the client": {
			cfg:       Config{},
			clientKey: "Remote-Client-IP", wantKey: "remote-client-ip", want: []string{spoof},
		},
		"operator extra": {
			cfg:       Config{ExtraUserHeaders: map[string][]string{"Tenant": {"acme"}}},
			clientKey: "tenant", wantKey: "Tenant", want: []string{"acme"},
		},
		"key the proxy does not write": {
			cfg:       Config{ExtraUserHeadersClientIPEnabled: true, ExtraUserHeaders: map[string][]string{"Tenant": {"acme"}}},
			clientKey: "acme.io/team", wantKey: "acme.io/team", want: []string{spoof},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			imp, reviewer := impersonateBob(t, tc.cfg, inbound, map[string]string{tc.clientKey: spoof})
			assertExtraAuthorized(t, reviewer, strings.ToLower(tc.clientKey), spoof)

			// Exactly one key per canonical header, carrying exactly one
			// source's values.
			var keys []string
			for k := range imp.Outbound.Extra {
				if strings.EqualFold(k, tc.wantKey) {
					keys = append(keys, k)
				}
			}
			if len(keys) != 1 || keys[0] != tc.wantKey {
				t.Fatalf("forwarded keys matching %q = %q, want exactly [%q]", tc.wantKey, keys, tc.wantKey)
			}
			if got := imp.Outbound.Extra[tc.wantKey]; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("extra %s = %q, want %q", tc.wantKey, got, tc.want)
			}
		})
	}
}

// impersonateBob serves a request authenticated as inbound that impersonates
// bob with the given Impersonate-Extra- headers, every review allowed, and
// returns how it is forwarded and what the reviews asked.
func impersonateBob(t *testing.T, cfg Config, inbound authuser.Info, extras map[string]string) (*reqctx.ImpersonationRecord, *attributeRecordingReviewer) {
	t.Helper()

	reviewer := &attributeRecordingReviewer{FakeReviewer: fakesubjectaccessreview.New(nil)}
	sar := subjectaccessreview.New(reviewer, subjectaccessreview.Config{MaxHeaderValues: subjectaccessreview.DefaultMaxHeaderValues}, slog.New(slog.DiscardHandler))
	p := newTestProxy(t, withSubjectAccessReviewer(sar))
	p.config = &cfg

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Impersonate-User", "bob")
	for k, v := range extras {
		req.Header.Set("Impersonate-Extra-"+k, v)
	}
	req = req.WithContext(genericapirequest.WithUser(logging.WithRequestID(req.Context(), "test-request-id"), inbound))

	var imp *reqctx.ImpersonationRecord
	p.withImpersonateRequest(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		imp = reqctx.Impersonation(r)
	})).ServeHTTP(httptest.NewRecorder(), req)
	if imp == nil {
		t.Fatalf("an allowed impersonation was not served: %s", p.logs.Raw())
	}
	return imp, reviewer
}

// assertExtraAuthorized checks a SubjectAccessReview asked whether the
// requester may impersonate key=value, so dropping the value from the
// forwarded request never skipped its authorization.
func assertExtraAuthorized(t *testing.T, reviewer *attributeRecordingReviewer, key, value string) {
	t.Helper()
	if !slices.ContainsFunc(reviewer.asked, func(a azv1.ResourceAttributes) bool {
		return a.Resource == "userextras" && a.Subresource == key && a.Name == value
	}) {
		t.Errorf("the client's %s extra was not authorized: reviews = %+v", key, reviewer.asked)
	}
}

// TestOutboundGroupsMirrorTheAPIServer pins the groups the forwarded identity
// carries to the ones kube-apiserver's impersonation filter would give it, so
// impersonating through the proxy and impersonating directly agree. The
// resolved groups, such as a service account's, are forwarded as they are.
func TestOutboundGroupsMirrorTheAPIServer(t *testing.T) {
	inbound := &authuser.DefaultInfo{Name: "alice", Groups: []string{"devs"}}

	tests := map[string]struct {
		target authuser.Info
		want   []string
	}{
		"no impersonation": {nil, []string{"devs", authuser.AllAuthenticated}},
		"user": {&authuser.DefaultInfo{Name: "bob", Groups: []string{"ops"}},
			[]string{"ops", authuser.AllAuthenticated}},
		"user already authenticated": {&authuser.DefaultInfo{Name: "bob", Groups: []string{authuser.AllAuthenticated}},
			[]string{authuser.AllAuthenticated}},
		"user asking for unauthenticated": {&authuser.DefaultInfo{Name: "bob", Groups: []string{authuser.AllUnauthenticated}},
			[]string{authuser.AllUnauthenticated}},
		"anonymous": {&authuser.DefaultInfo{Name: authuser.Anonymous},
			[]string{authuser.AllUnauthenticated}},
		"anonymous with unauthenticated": {&authuser.DefaultInfo{Name: authuser.Anonymous, Groups: []string{authuser.AllUnauthenticated}},
			[]string{authuser.AllUnauthenticated}},
		"service account": {&authuser.DefaultInfo{Name: "system:serviceaccount:ns:sa",
			Groups: []string{serviceaccount.AllServiceAccountsGroup, "system:serviceaccounts:ns"}},
			[]string{serviceaccount.AllServiceAccountsGroup, "system:serviceaccounts:ns", authuser.AllAuthenticated}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)
			out, err := p.outboundIdentity(newFakeR(), inbound, tc.target)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(out.Groups, tc.want) {
				t.Errorf("groups = %q, want %q", out.Groups, tc.want)
			}
		})
	}
}
