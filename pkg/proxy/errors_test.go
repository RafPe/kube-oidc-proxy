// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"bytes"
	stdcontext "context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/tokenreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
)

func newFakeR() *http.Request {
	return withTestRequestID(&http.Request{
		Method:     http.MethodGet,
		RemoteAddr: "1.2.3.4:5555",
		URL:        &url.URL{Path: "/api/v1/pods"},
	})
}

func newFakeRW() *fakeRW {
	return &fakeRW{
		header: make(http.Header),
		buffer: make([]byte, 0),
	}
}

func tryError(t *testing.T, expCode int, err error) (*fakeRW, *logtest.Capture) {
	return tryHandler(t, expCode, err, (*Proxy).refuse)
}

// tryHandler serves err through one of the proxy's two error handlers and
// checks the status it answered with.
func tryHandler(t *testing.T, expCode int, err error, handle func(*Proxy, http.ResponseWriter, *http.Request, error)) (*fakeRW, *logtest.Capture) {
	t.Helper()
	p := newTestProxy(t)

	frw := newFakeRW()
	fr := newFakeR()

	handle(p.Proxy, frw, fr, err)

	code, err := strconv.Atoi(frw.header.Get("StatusCode"))
	if err != nil {
		t.Errorf(
			"failed to get status code from response header: %s",
			err)
	}

	if code != expCode {
		t.Errorf("unexpected status code, exp=%d got=%d",
			expCode, code)
	}

	return frw, p.logs
}

func TestError(t *testing.T) {
	frw, records := tryError(t, http.StatusUnauthorized, errUnauthorized)
	if exp := []byte("Unauthorized\n"); !bytes.Equal(frw.buffer, exp) {
		t.Errorf("unexpected response, exp='%s' got='%s'", exp, frw.buffer)
	}
	assertDeniedReason(t, records, metrics.ReasonUnauthorized)

	frw, records = tryError(t, http.StatusForbidden, errNoUsername)
	if exp := []byte("Username claim not available in OIDC Issuer response\n"); !bytes.Equal(frw.buffer, exp) {
		t.Errorf("unexpected response, exp='%s' got='%s'", exp, frw.buffer)
	}
	assertDeniedReason(t, records, metrics.ReasonNoUsernameClaim)

	frw, records = tryError(t, http.StatusInternalServerError, errors.New("foo"))
	if exp := []byte("\n"); !bytes.Equal(frw.buffer, exp) {
		t.Errorf("unexpected response, exp='%s' got='%s'", exp, frw.buffer)
	}
	assertDeniedReason(t, records, metrics.ReasonInternalError)
}

// TestErrorHandlerInternalFailureEmitsHandlerFailed pins the record the proxy
// writes when it failed for its own reasons rather than the client's. Every
// internal-error branch of the error handler reports request.handler.failed at
// ERROR, carrying the bounded error text that the client-facing empty 500 body
// deliberately withholds.
func TestErrorHandlerInternalFailureEmitsHandlerFailed(t *testing.T) {
	tests := map[string]struct {
		err            error
		wantErrMessage string
	}{
		"forwarding decision missing": {
			err:            errNoForwardDecision,
			wantErrMessage: errNoForwardDecision.Error(),
		},
		"unclassified error": {
			err:            errors.New("boom"),
			wantErrMessage: "boom",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)

			p.refuse(newFakeRW(), newFakeR(), test.err)

			rec := p.logs.Only(t, logging.EventRequestHandlerFailed)
			if got := rec.String("level"); got != "ERROR" {
				t.Errorf("level = %q, want ERROR", got)
			}
			if got := rec.String("component"); got != string(logging.ComponentRequest) {
				t.Errorf("component = %q, want %q", got, logging.ComponentRequest)
			}
			if got := rec.String("request_id"); got != "test-request-id" {
				t.Errorf("request_id = %q, want %q", got, "test-request-id")
			}
			if got := rec.String("reason"); got != string(metrics.ReasonInternalError) {
				t.Errorf("reason = %q, want %q", got, metrics.ReasonInternalError)
			}
			if got := rec.String("error_message"); got != test.wantErrMessage {
				t.Errorf("error_message = %q, want %q", got, test.wantErrMessage)
			}
		})
	}
}

// assertDeniedReason pins the single AuFail record a refusal writes, and the
// closed reason it is classified by.
func assertDeniedReason(t *testing.T, records *logtest.Capture, wantReason metrics.Reason) {
	t.Helper()
	rec := records.Only(t, logging.EventRequestAccessDecided)
	if got := rec.String("event"); got != "AuFail" {
		t.Errorf("event = %q, want AuFail", got)
	}
	if got := rec.String("decision"); got != "deny" {
		t.Errorf("decision = %q, want deny", got)
	}
	if got := rec.String("reason"); got != string(wantReason) {
		t.Errorf("reason = %q, want %q", got, wantReason)
	}
}

// TestErrorClassifiesEveryReason pins the whole reason map in one place: every
// error the proxy classifies produces its own closed reason value, so a query
// on reason can distinguish a 401 from a 403 from an upstream failure.
func TestErrorClassifiesEveryReason(t *testing.T) {
	tests := map[string]struct {
		err       error
		expCode   int
		expReason metrics.Reason
	}{
		"unauthorized": {errUnauthorized, http.StatusUnauthorized, metrics.ReasonUnauthorized},
		// The proxy fails closed, so the client sees the 401 a rejected token
		// gets; only the reason says the reviewer could not answer.
		"token review unavailable": {errReviewUnavailable,
			http.StatusUnauthorized, metrics.ReasonAuthenticationDependencyError},
		"reserved identity": {fmt.Errorf("%w: username %q", errReservedIdentity, "system:masters"),
			http.StatusForbidden, metrics.ReasonReservedIdentity},
		"no username claim": {errNoUsername, http.StatusForbidden, metrics.ReasonNoUsernameClaim},
		"too many impersonation values": {fmt.Errorf("%w: 5 > 2", subjectaccessreview.ErrTooManyImpersonationHeaderValues),
			http.StatusRequestHeaderFieldsTooLarge, metrics.ReasonTooManyImpersonationValues},
		"impersonation denied": {&subjectaccessreview.ImpersonationAuthError{
			Requester: "mmosley", Kind: subjectaccessreview.TargetGroup, Target: "system:masters"},
			http.StatusForbidden, metrics.ReasonImpersonationDenied},
		"no forwarding decision": {errNoForwardDecision, http.StatusInternalServerError, metrics.ReasonInternalError},
		// A SubjectAccessReview that could not be submitted wraps a client-go
		// transport error. It is the proxy's own dependency failing, not the
		// upstream hop, so it is a 500 and never a 502.
		"subjectaccessreview unavailable": {fmt.Errorf("%w: %w", subjectaccessreview.ErrCreateSubjectAccessReview,
			&net.OpError{Op: "dial", Err: errors.New("connection refused")}),
			http.StatusInternalServerError, metrics.ReasonAuthorizationDependencyError},
		// Refused by shape, like its unknown-header sibling, so the same 400.
		"no impersonation user": {subjectaccessreview.ErrNoImpersonationUser, http.StatusBadRequest, metrics.ReasonMalformedImpersonation},
		"unknown impersonation header": {fmt.Errorf("%w: %q", subjectaccessreview.ErrUnknownImpersonationHeader, "Impersonate-Foo"),
			http.StatusBadRequest, metrics.ReasonMalformedImpersonation},
		"unforwardable extra key": {fmt.Errorf("%w: %q", subjectaccessreview.ErrUnforwardableExtraKey, "Impersonate-Extra-%41bc"),
			http.StatusBadRequest, metrics.ReasonMalformedImpersonation},
		"unknown": {errors.New("boom"), http.StatusInternalServerError, metrics.ReasonInternalError},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, records := tryError(t, test.expCode, test.err)
			assertDeniedReason(t, records, test.expReason)
		})
	}
}

// TestUpstreamTransportFailureIsNotAnAccessDecision pins the one-record rule:
// the access decision is written exactly once per request, by roundTrip, at
// the moment the request is admitted. A transport failure afterwards is not a
// second decision -- the request was already allowed -- so the upstream error
// handler answers 502 and reports the failure on its own upstream record.
func TestUpstreamTransportFailureIsNotAnAccessDecision(t *testing.T) {
	_, records := tryHandler(t, http.StatusBadGateway,
		&net.OpError{Op: "dial", Err: errors.New("connection refused")}, (*Proxy).handleUpstreamError)

	if got := records.ByEvent(logging.EventRequestAccessDecided); len(got) != 0 {
		t.Fatalf("the upstream error handler wrote %d access records for a transport failure: %s",
			len(got), records.Raw())
	}
	if got := records.Only(t, logging.EventUpstreamRequestFailed).String("reason"); got != string(metrics.ReasonUpstreamError) {
		t.Errorf("reason = %q, want %q", got, metrics.ReasonUpstreamError)
	}
}

// TestUpstreamNonTransportFailureIsInternal pins the upstream handler's other
// branch: an error that is not the transport's -- roundTrip finding no
// forwarding decision on the request -- is the proxy's own failure, a 500
// with request.handler.failed, and never a 502.
func TestUpstreamNonTransportFailureIsInternal(t *testing.T) {
	_, records := tryHandler(t, http.StatusInternalServerError, errNoForwardDecision, (*Proxy).handleUpstreamError)

	records.Only(t, logging.EventRequestHandlerFailed)
	assertDeniedReason(t, records, metrics.ReasonInternalError)
	if got := records.ByEvent(logging.EventUpstreamRequestFailed); len(got) != 0 {
		t.Fatalf("a non-transport error was reported as an upstream failure: %s", records.Raw())
	}
}

// TestErrorCanceledIsRecordedWithoutAResponse pins the filter-phase cancel: the
// client went away while its impersonation was being authorized. Nothing is
// written back, the request still produced a decision that has to be
// recorded, and no upstream record is emitted, because no upstream call was
// ever made.
func TestErrorCanceledIsRecordedWithoutAResponse(t *testing.T) {
	p := newTestProxy(t)

	ctx, cancel := stdcontext.WithCancel(stdcontext.Background())
	cancel()

	frw := newFakeRW()
	p.refuse(frw, withTestRequestID(newFakeR().WithContext(ctx)),
		fmt.Errorf("%w: %w", subjectaccessreview.ErrCreateSubjectAccessReview, stdcontext.Canceled))

	if got := frw.header.Get("StatusCode"); got != "" {
		t.Errorf("a status code was written for a canceled request: %q", got)
	}
	assertDeniedReason(t, p.logs, metrics.ReasonClientCanceled)
	if got := p.logs.ByEvent(logging.EventUpstreamRequestCanceled); len(got) != 0 {
		t.Fatalf("a cancel before any upstream call was reported as an upstream cancel: %s", p.logs.Raw())
	}
}

// TestDependencyFailureIsNotAHandlerFailure pins that a TokenReview or
// SubjectAccessReview the API server could not answer is reported once, by
// the reviewer that saw it, and not again as request.handler.failed: the
// failure is the dependency's, not the proxy's own. The access-decision
// metric carries the same dependency reason the record does.
func TestDependencyFailureIsNotAHandlerFailure(t *testing.T) {
	tests := map[string]struct {
		err        error
		wantReason metrics.Reason
	}{
		"token review": {errReviewUnavailable,
			metrics.ReasonAuthenticationDependencyError},
		"subject access review": {fmt.Errorf("%w: %w", subjectaccessreview.ErrCreateSubjectAccessReview,
			stdcontext.DeadlineExceeded), metrics.ReasonAuthorizationDependencyError},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)
			p.refuse(newFakeRW(), newFakeR(), test.err)
			if got := p.logs.ByEvent(logging.EventRequestHandlerFailed); len(got) != 0 {
				t.Fatalf("a dependency failure was also reported as the proxy's own: %s", p.logs.Raw())
			}
			if v, _ := metricstest.Value(t, p.metrics.Gatherer(), metricAccessDecisions,
				map[string]string{"decision": "deny", "reason": string(test.wantReason)}); v != 1 {
				t.Errorf("decisions{deny,%s} = %v, want 1", test.wantReason, v)
			}
		})
	}
}

// TestErrorRequesterDeadlineIsClientCanceled pins the SubjectAccessReview
// classification for a request whose own context ended: the review failed
// because the client went away, not because the API server did not answer,
// so the access record agrees with authz.sar.failed's client_canceled.
func TestErrorRequesterDeadlineIsClientCanceled(t *testing.T) {
	p := newTestProxy(t)

	ctx, cancel := stdcontext.WithCancel(stdcontext.Background())
	cancel()
	req := newFakeR()
	req = req.WithContext(ctx)

	frw := newFakeRW()
	p.refuse(frw, withTestRequestID(req), fmt.Errorf("%w: %w", subjectaccessreview.ErrCreateSubjectAccessReview, stdcontext.DeadlineExceeded))

	if got := frw.header.Get("StatusCode"); got != "" {
		t.Errorf("a status code was written for a request whose client went away: %q", got)
	}
	assertDeniedReason(t, p.logs, metrics.ReasonClientCanceled)
}

// TestErrorClientGoneNeedsBothSignals pins that refuse demotes a failure to
// client_canceled by ctxerr.ClientGone, the predicate the reviews use: only a
// context error on a request whose own context has ended. A cancellation
// while the client is still attached is the proxy's own failure, and a
// non-context review failure while the client hangs up is still the
// dependency's, so the access record agrees with the review's own record.
// handleUpstreamError applies the same rule; see
// TestUpstreamCancelWithClientAttachedIsInternal.
func TestErrorClientGoneNeedsBothSignals(t *testing.T) {
	ended, cancel := stdcontext.WithCancel(stdcontext.Background())
	cancel()

	tests := map[string]struct {
		ctx       stdcontext.Context
		err       error
		expCode   int
		expReason metrics.Reason
	}{
		"bare cancellation, client still attached": {stdcontext.Background(), stdcontext.Canceled,
			http.StatusInternalServerError, metrics.ReasonInternalError},
		"review answered 500 as the client hung up": {ended,
			fmt.Errorf("%w: %w", subjectaccessreview.ErrCreateSubjectAccessReview, errors.New("apiserver 500")),
			http.StatusInternalServerError, metrics.ReasonAuthorizationDependencyError},
		"token review status error as the client hung up": {ended,
			fmt.Errorf("%w: status error: boom", tokenreview.ErrCreateTokenReview),
			http.StatusUnauthorized, metrics.ReasonAuthenticationDependencyError},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)
			frw := newFakeRW()
			p.refuse(frw, withTestRequestID(newFakeR().WithContext(test.ctx)), test.err)

			if got := frw.header.Get("StatusCode"); got != strconv.Itoa(test.expCode) {
				t.Errorf("status = %q, want %d", got, test.expCode)
			}
			assertDeniedReason(t, p.logs, test.expReason)
		})
	}
}

// TestErrorImpersonationDenialNamesTheTarget pins that the refused target is
// carried as structured fields taken from the typed error, so nobody has to
// parse it back out of the client-facing message.
func TestErrorImpersonationDenialNamesTheTarget(t *testing.T) {
	tests := map[string]struct {
		err                  *subjectaccessreview.ImpersonationAuthError
		expKind, expTargetNm string
	}{
		"group": {&subjectaccessreview.ImpersonationAuthError{Kind: subjectaccessreview.TargetGroup, Target: "system:masters"}, "group", "system:masters"},
		"user":  {&subjectaccessreview.ImpersonationAuthError{Kind: subjectaccessreview.TargetUser, Target: "a-user"}, "user", "a-user"},
		"uid":   {&subjectaccessreview.ImpersonationAuthError{Kind: subjectaccessreview.TargetUID, Target: "bar"}, "uid", "bar"},
		"extra": {&subjectaccessreview.ImpersonationAuthError{Kind: subjectaccessreview.TargetExtra, ExtraKey: "foo", Target: "bar"}, "extra", "foo=bar"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.err.Requester = "mmosley"
			_, records := tryError(t, http.StatusForbidden, test.err)
			rec := records.Only(t, logging.EventRequestAccessDecided)
			if got := rec.String("target_kind"); got != test.expKind {
				t.Errorf("target_kind = %q, want %q", got, test.expKind)
			}
			if got := rec.String("target_name"); got != test.expTargetNm {
				t.Errorf("target_name = %q, want %q", got, test.expTargetNm)
			}
		})
	}
}
