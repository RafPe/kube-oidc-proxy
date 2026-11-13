// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"go.uber.org/mock/gomock"
	azv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authuser "k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
	fakesubjectaccessreview "github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview/fake"
)

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

// TestTokenReviewDependencyFailureIsError separates the two ways a TokenReview
// can fail to admit a request. An API server that could not answer is an
// operator-visible dependency failure carrying the error text; it is not a
// verdict on the credential, so it must not be recorded as a completed review.
func TestTokenReviewDependencyFailureIsError(t *testing.T) {
	p := newTestProxy(t)
	p.fakeReviewer.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
		nil, false, errors.New("apiserver unreachable"))

	req := reservedIdentityRequest(t, nil)

	if err := p.reviewToken(req); !errors.Is(err, errTokenReviewUnavailable) {
		t.Fatalf("reviewToken = %v, want errTokenReviewUnavailable: the path must fail closed", err)
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

// TestTokenReviewClientDisconnectIsNotAnError pins the other side of that
// split: a review that failed because the client itself hung up is not the
// API server's fault, so it is recorded at DEBUG as client_canceled, and the
// request is refused without a response and without any ERROR record a
// client could drive by disconnecting.
func TestTokenReviewClientDisconnectIsNotAnError(t *testing.T) {
	p := newTestProxy(t)
	p.config = &Config{TokenPassthrough: true}

	ctx, cancel := context.WithCancel(context.Background())
	req := reservedIdentityRequest(t, nil)
	req = req.WithContext(ctx)
	req = withTestRequestID(req)

	p.fakeReviewer.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		func(context.Context, string) (*authenticator.Response, bool, error) {
			cancel()
			return nil, false, fmt.Errorf("review: %w", context.Canceled)
		})

	rw := httptest.NewRecorder()
	p.withTokenReview(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a request whose review failed reached the next handler")
	})).ServeHTTP(rw, req)

	rec := p.logs.Only(t, logging.EventAuthnTokenReviewFailed)
	if got := rec.String("level"); got != "DEBUG" {
		t.Errorf("level = %q, want DEBUG", got)
	}
	if got := rec.String("reason"); got != string(metrics.ReasonClientCanceled) {
		t.Errorf("reason = %q, want %q", got, metrics.ReasonClientCanceled)
	}
	for _, r := range p.logs.Records() {
		if r.String("level") == "ERROR" {
			t.Errorf("a client disconnect produced an ERROR record: %v", r)
		}
	}
	if got := p.logs.Only(t, logging.EventRequestAccessDecided).String("reason"); got != string(metrics.ReasonClientCanceled) {
		t.Errorf("access reason = %q, want %q", got, metrics.ReasonClientCanceled)
	}
	if rw.Code != http.StatusOK || rw.Body.Len() != 0 {
		t.Errorf("a response was written for a client that went away: %d %q", rw.Code, rw.Body.String())
	}
}

// TestClientCancellationEmitsUpstreamRequestCanceled pins the upstream cancel:
// the client went away while the API server was answering, so nothing is
// written back. It is routine, so the record is DEBUG. The access decision is
// RoundTrip's, written before the upstream call; the error handler writes
// none of its own.
func TestClientCancellationEmitsUpstreamRequestCanceled(t *testing.T) {
	p := newTestProxy(t)

	req := reservedIdentityRequest(t, nil)
	rw := httptest.NewRecorder()
	p.handleUpstreamError(rw, req, context.Canceled)

	rec := p.logs.Only(t, logging.EventUpstreamRequestCanceled)
	assertRecord(t, rec, logging.EventUpstreamRequestCanceled, logging.ComponentUpstream, "test-request-id")
	if got := rec.String("level"); got != "DEBUG" {
		t.Errorf("level = %q, want DEBUG", got)
	}
	if got := rec.String("reason"); got != string(metrics.ReasonClientCanceled) {
		t.Errorf("reason = %q, want %q", got, metrics.ReasonClientCanceled)
	}
	if got := p.logs.ByEvent(logging.EventRequestAccessDecided); len(got) != 0 {
		t.Errorf("the upstream error handler wrote an access decision: %s", p.logs.Raw())
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
	req = reqctx.WithRequestID(req, "rid-1")
	req = req.WithContext(logging.WithRequestID(req.Context(), "rid-1"))
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
	req = req.WithContext(logging.WithRequestID(req.Context(), "rid-2"))
	p.reviewToken(req)
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
	if err := p.reviewToken(req); !errors.Is(err, errUnauthorized) {
		t.Fatalf("reviewToken = %v, want errUnauthorized for a rejected token", err)
	}
	if got := p.logs.ByEvent(logging.EventAuthnTokenReviewFailed); len(got) != 0 {
		t.Errorf("a rejected token was recorded as a failure: %s", p.logs.Raw())
	}
	if got := p.logs.ByEvent(logging.EventAuthnTokenReviewCompleted); len(got) != 0 {
		t.Errorf("the proxy emitted a completion record the reviewer already owns: %s", p.logs.Raw())
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

// TestUpstreamErrorHandlerClassifiesTransportErrors pins the upstream handler:
// a transport failure on the hop to the API server is answered 502, carries a
// classified termination on its own upstream record, and never writes a second
// access decision -- RoundTrip already recorded the admission.
func TestUpstreamErrorHandlerClassifiesTransportErrors(t *testing.T) {
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
			p.handleUpstreamError(rw, req, c.err)
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
	reverseProxy.ErrorHandler = p.handleUpstreamError

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
