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

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/accesslog"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
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
	p := new(Proxy)
	access, records := newAccessLogger(t)
	p.access = access
	p.handleError = p.newErrorHandler()

	frw := newFakeRW()
	fr := newFakeR()

	p.handleError(frw, fr, err)

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

	return frw, records
}

func TestError(t *testing.T) {
	// no error
	frw, records := tryError(t, http.StatusInternalServerError, nil)
	if len(frw.buffer) != 1 {
		t.Errorf("unexpected response, exp='\n' got='%s'", frw.buffer)
	}
	// Nothing was decided about a request, so nothing is recorded about one.
	if got := records.ByEvent(logging.EventRequestAccessDecided); len(got) != 0 {
		t.Errorf("an access record was written for a nil error: %s", records.Raw())
	}

	frw, records = tryError(t, http.StatusUnauthorized, errUnauthorized)
	if exp := []byte("Unauthorized\n"); !bytes.Equal(frw.buffer, exp) {
		t.Errorf("unexpected response, exp='%s' got='%s'", exp, frw.buffer)
	}
	assertDeniedReason(t, records, metrics.ReasonUnauthorized)

	frw, records = tryError(t, http.StatusForbidden, errNoName)
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
		"called with no error": {
			err:            nil,
			wantErrMessage: "error handler called with nil error",
		},
		"impersonation configuration missing": {
			err:            errNoImpersonationConfig,
			wantErrMessage: errNoImpersonationConfig.Error(),
		},
		"unclassified error": {
			err:            errors.New("boom"),
			wantErrMessage: "boom",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			root, records := logtest.New(t, 0)
			requestLogger := logging.ForComponent(root, logging.ComponentRequest)
			p := &Proxy{
				logger: requestLogger,
				access: accesslog.NewAccessLogger(requestLogger),
			}
			p.handleError = p.newErrorHandler()

			p.handleError(newFakeRW(), newFakeR(), test.err)

			rec := records.Only(t, logging.EventRequestHandlerFailed)
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
		"reserved identity": {fmt.Errorf("%w: username %q", errReservedIdentity, "system:masters"),
			http.StatusForbidden, metrics.ReasonReservedIdentity},
		"no username claim": {errNoName, http.StatusForbidden, metrics.ReasonNoUsernameClaim},
		"too many impersonation values": {fmt.Errorf("%w: 5 > 2", subjectaccessreview.ErrTooManyImpersonationHeaderValues),
			http.StatusRequestHeaderFieldsTooLarge, metrics.ReasonTooManyImpersonationValues},
		"impersonation denied": {&subjectaccessreview.ImpersonationAuthError{
			Requester: "mmosley", Kind: subjectaccessreview.TargetGroup, Target: "system:masters"},
			http.StatusForbidden, metrics.ReasonImpersonationDenied},
		"no impersonation config": {errNoImpersonationConfig, http.StatusInternalServerError, metrics.ReasonInternalError},
		// A SubjectAccessReview that could not be submitted wraps a client-go
		// transport error, so it satisfies net.Error too. It is the proxy's own
		// dependency failing, not the upstream hop, so it stays a 500.
		"subjectaccessreview unavailable": {fmt.Errorf("%w: %w", subjectaccessreview.ErrCreateSubjectAccessReview,
			&net.OpError{Op: "dial", Err: errors.New("connection refused")}),
			http.StatusInternalServerError, metrics.ReasonInternalError},
		"no impersonation user": {subjectaccessreview.ErrNoImpersonationUser, http.StatusInternalServerError, metrics.ReasonInternalError},
		"unknown":               {errors.New("boom"), http.StatusInternalServerError, metrics.ReasonInternalError},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, records := tryError(t, test.expCode, test.err)
			assertDeniedReason(t, records, test.expReason)
		})
	}
}

// TestErrorUpstreamTransportFailureIsNotAnAccessDecision pins the one-record
// rule: the access decision is written exactly once per request, by RoundTrip,
// at the moment the request is admitted. A transport failure afterwards is not
// a second decision -- the request was already allowed -- so the error handler
// records nothing here and answers 502. Task 14 adds the upstream event that
// carries the failure itself.
func TestErrorUpstreamTransportFailureIsNotAnAccessDecision(t *testing.T) {
	_, records := tryError(t, http.StatusBadGateway,
		&net.OpError{Op: "dial", Err: errors.New("connection refused")})

	if got := records.ByEvent(logging.EventRequestAccessDecided); len(got) != 0 {
		t.Fatalf("the error handler wrote %d access records for a transport failure: %s",
			len(got), records.Raw())
	}
}

// TestErrorCanceledIsRecordedWithoutAResponse pins the one branch that writes
// no response: the connection is already going away, but the request still
// produced a decision that has to be recorded.
func TestErrorCanceledIsRecordedWithoutAResponse(t *testing.T) {
	p := new(Proxy)
	access, records := newAccessLogger(t)
	p.access = access
	p.handleError = p.newErrorHandler()

	frw := newFakeRW()
	p.handleError(frw, newFakeR(), stdcontext.Canceled)

	if got := frw.header.Get("StatusCode"); got != "" {
		t.Errorf("a status code was written for a canceled request: %q", got)
	}
	assertDeniedReason(t, records, metrics.ReasonClientCanceled)
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
