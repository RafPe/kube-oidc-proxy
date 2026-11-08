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
	"net/http/httputil"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"go.uber.org/mock/gomock"
	azv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
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
	if got := rec.String("reason"); got != string(metrics.ReasonAuthenticationDependencyError) {
		t.Errorf("reason = %q, want %q", got, metrics.ReasonAuthenticationDependencyError)
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
	if got := rec.String("reason"); got != string(metrics.ReasonClientCanceled) {
		t.Errorf("reason = %q, want %q", got, metrics.ReasonClientCanceled)
	}
	assertDeniedReason(t, p.logs, metrics.ReasonClientCanceled)
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
	req = reqctx.WithRequestID(req, "rid-1")
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

// TestRejectedTokenReviewIsNotAFailure pins that a TokenReview which answered
// "not authenticated" is denied without a failure record, and that the proxy
// adds no completion record of its own: the reviewer that answered emits
// authn.tokenreview.completed (with duration_ms on a live call), so a second
// one here would double-count every live review.
func TestRejectedTokenReviewIsNotAFailure(t *testing.T) {
	p := newTestProxy(t)
	p.fakeReviewer.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(nil, false, nil)
	req := reservedIdentityRequest(t, nil)
	req = req.WithContext(logging.NewContext(req.Context(), p.logger))
	if p.reviewToken(httptest.NewRecorder(), req) {
		t.Fatal("a rejected token passed review")
	}
	if got := p.logs.ByEvent(logging.EventAuthnTokenReviewFailed); len(got) != 0 {
		t.Errorf("a rejected token was recorded as a failure: %s", p.logs.Raw())
	}
	if got := p.logs.ByEvent(logging.EventAuthnTokenReviewCompleted); len(got) != 0 {
		t.Errorf("the proxy emitted a completion record the reviewer already owns: %s", p.logs.Raw())
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

// TestErrorHandlerClassifiesUpstreamTransportErrors pins the upstream branch:
// a transport failure on the hop to the API server is answered 502, carries a
// classified termination on its own upstream record, and never writes a second
// access decision -- RoundTrip already recorded the admission.
func TestErrorHandlerClassifiesUpstreamTransportErrors(t *testing.T) {
	cases := map[string]struct {
		err  error
		term metrics.Termination
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
			if up.String("termination") != string(c.term) || up.String("reason") != string(metrics.ReasonUpstreamError) {
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

// cancelingRT stands in for the transport carrying an admitted request to the
// API server when the client gives up while the call is still in flight. It
// cancels the request the way a disconnecting client does, waits for the
// cancellation to land, and returns the context error that
// httputil.ReverseProxy hands to the error handler.
type cancelingRT struct{ cancel context.CancelFunc }

func (c *cancelingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.cancel()
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// TestClientCancelAfterAdmissionRecordsOneAccessDecision drives an authorized
// request through the whole chain into the reverse proxy and takes the client
// away before the upstream answers. RoundTrip has already written the AuSuccess
// access record, so the cancel that follows must not write a second, AuFail
// one: a kubectl call abandoned during a slow apiserver patch would otherwise
// manufacture an authorization failure for a user who was allowed through.
func TestClientCancelAfterAdmissionRecordsOneAccessDecision(t *testing.T) {
	p := newTestProxy(t)
	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		oidcAnswer(&authenticator.Response{User: &authuser.DefaultInfo{Name: "alice"}}, true, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.clientTransport = &cancelingRT{cancel: cancel}

	target, err := url.Parse("https://127.0.0.1:6443")
	if err != nil {
		t.Fatal(err)
	}
	reverseProxy := httputil.NewSingleHostReverseProxy(target)
	reverseProxy.Transport = p.Proxy
	reverseProxy.ErrorHandler = p.handleError

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil).WithContext(ctx)
	req.RemoteAddr = "1.2.3.4:5555"
	req.Header.Set("Authorization", "bearer fake-token")

	serveChain(t, p, req, reverseProxy.ServeHTTP)

	decided := p.logs.ByEvent(logging.EventRequestAccessDecided)
	if len(decided) != 1 {
		t.Fatalf("access decisions = %d, want 1: %s", len(decided), p.logs.Raw())
	}
	if got := decided[0].String("event"); got != "AuSuccess" {
		t.Errorf("event = %q, want AuSuccess: %v", got, decided[0])
	}
	if n := len(p.logs.ByEvent(logging.EventUpstreamRequestCanceled)); n != 1 {
		t.Errorf("upstream.request.canceled records = %d, want 1: %s", n, p.logs.Raw())
	}
	if got := p.logs.Only(t, logging.EventRequestResponseCompleted).String("termination"); got != string(metrics.TerminationClientCancel) {
		t.Errorf("termination = %q, want %q", got, metrics.TerminationClientCancel)
	}
}
