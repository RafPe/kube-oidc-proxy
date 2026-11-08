// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	stdcontext "context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/server"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/accesslog"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/hooks"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/mocks"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	fakesubjectaccessreview "github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview/fake"
)

type fakeProxy struct {
	ctrl *gomock.Controller

	fakeToken    *mocks.MockToken
	fakeReviewer *mocks.MockToken
	fakeRT       *fakeRT

	// logs is the capture every component of this proxy writes into.
	logs *logtest.Capture
	*Proxy
}

// newAccessLogger builds an access logger writing into a capture, so a test can
// assert on the records a request produced.
func newAccessLogger(t *testing.T) (*accesslog.AccessLogger, *logtest.Capture) {
	t.Helper()
	root, records := logtest.New(t, 0)
	return accesslog.NewAccessLogger(logging.ForComponent(root, logging.ComponentRequest)), records
}

// testIssuerName is the issuer the fake OIDC authenticator attributes an
// accepted token to, standing in for the AttributeToIssuer wrapper run.go puts
// around every configured issuer's authenticator.
const testIssuerName = "corp"

// oidcAnswer returns a fake AuthenticateToken body that answers with resp and,
// when it accepted the token, names testIssuerName on the request the way the
// AttributeToIssuer wrapper does in production. Every success path needs it:
// authn.oidc.succeeded requires a non-empty issuer_name.
func oidcAnswer(resp *authenticator.Response, ok bool, err error) func(stdcontext.Context, string) (*authenticator.Response, bool, error) {
	return func(ctx stdcontext.Context, _ string) (*authenticator.Response, bool, error) {
		if ok && err == nil {
			authn.RecordIssuer(ctx, testIssuerName)
		}
		return resp, ok, err
	}
}

// withTestRequestID stamps the correlation id the request-id filter mints in
// production. Every access record is required to carry one.
func withTestRequestID(req *http.Request) *http.Request {
	return reqctx.WithRequestID(req, "test-request-id")
}

type fakeRW struct {
	buffer []byte
	header http.Header
}

type fakeRT struct {
	t *testing.T

	expUser  string
	expGroup []string
	expExtra map[string][]string
	expUID   string
}

func (f *fakeRW) Write(b []byte) (int, error) {
	f.buffer = append(f.buffer, b...)
	return len(b), nil
}

func (f *fakeRW) WriteHeader(code int) {
	f.header.Add("StatusCode", strconv.Itoa(code))
}

func (f *fakeRW) Header() http.Header {
	return f.header
}

func (f *fakeRT) RoundTrip(h *http.Request) (*http.Response, error) {
	if h.Header.Get("Impersonate-User") != f.expUser {
		f.t.Errorf("client transport got unexpected user impersonation header, exp=%s got=%s",
			f.expUser, h.Header.Get("Impersonate-User"))
	}

	if h.Header.Get("Impersonate-Uid") != f.expUID {
		f.t.Errorf("client transport got unexpected uid impersonation header, exp=%s got=%s",
			f.expUID, h.Header.Get("Impersonate-Uid"))
	}

	if exp, act := sort.StringSlice(f.expGroup), sort.StringSlice(h.Header["Impersonate-Group"]); !reflect.DeepEqual(exp, act) {
		f.t.Errorf(
			"client transport got unexpected group impersonation header, exp=%#v got=%#v",
			exp,
			act,
		)
	}

	for k, vv := range h.Header {
		if strings.HasPrefix(k, "Impersonate-Extra-") {
			expvv, ok := f.expExtra[k]
			if !ok {
				f.t.Errorf("got unexpected impersonate extra: %s", k)
				continue
			}

			if !reflect.DeepEqual(vv, expvv) {
				f.t.Errorf("unexpected values in impersonate extra (%s), exp=%s got=%s", k, expvv, vv)
			}
		}
	}

	for k, expvv := range f.expExtra {
		vv, ok := h.Header[k]
		if !ok {
			f.t.Errorf("did not get expected impersonate extra: %s", k)
			continue
		}

		if !reflect.DeepEqual(vv, expvv) {
			f.t.Errorf("unexpected values in impersonate extra (%s), exp=%s got=%s", k, expvv, vv)
		}
	}

	return nil, nil
}

// frozenClock is the instant the test warning limiter measures every bucket
// against, so a burst never refills mid-test.
var frozenClock = time.Unix(0, 0)

func newTestProxy(t *testing.T) *fakeProxy {
	ctrl := gomock.NewController(t)
	fakeToken := mocks.NewMockToken(ctrl)
	fakeReviewer := mocks.NewMockToken(ctrl)
	fakeRT := &fakeRT{t: t}

	// One root, one capture: every component the fake proxy owns writes into
	// the same stream, so a test can assert on any record the request produced
	// through fakeProxy.logs.
	root, logs := logtest.New(t, 2)
	trackCapture(logs)
	requestLogger := logging.ForComponent(root, logging.ComponentRequest)

	fakeSubjectAccessReviewer := fakesubjectaccessreview.New(nil)
	subjectAccessReview, _ := subjectaccessreview.New(fakeSubjectAccessReviewer, subjectaccessreview.Config{Timeout: subjectaccessreview.DefaultTimeout, AllowCacheTTL: 0, DenyCacheTTL: 0, MaxHeaderValues: subjectaccessreview.DefaultMaxHeaderValues}, logging.ForComponent(root, logging.ComponentSAR))

	// A real recorder, not a fake: the tests assert on the exposition the
	// binary would serve, including help strings and label names.
	recorder, err := metrics.New(metrics.BuildInfo{Version: "test", Revision: "test", GoVersion: "test"})
	if err != nil {
		t.Fatalf("metrics.New: %v", err)
	}

	p := &fakeProxy{
		ctrl:         ctrl,
		fakeToken:    fakeToken,
		fakeReviewer: fakeReviewer,
		fakeRT:       fakeRT,
		logs:         logs,
		Proxy: &Proxy{
			metrics:                  recorder,
			requestLogger:            requestLogger,
			oidcLogger:               logging.ForComponent(root, logging.ComponentOIDC),
			tokenReviewLogger:        logging.ForComponent(root, logging.ComponentTokenReview),
			upstreamLogger:           logging.ForComponent(root, logging.ComponentUpstream),
			access:                   accesslog.NewAccessLogger(requestLogger),
			oidcRequestAuthenticator: bearertoken.New(fakeToken),
			tokenReviewer:            fakeReviewer,
			subjectAccessReviewer:    subjectAccessReview,
			clientTransport:          fakeRT,
			noAuthClientTransport:    fakeRT,
			config:                   new(Config),
			hooks:                    hooks.New(logging.ForComponent(root, logging.ComponentShutdown)),
			// A frozen clock and a small burst make the warning limiter
			// deterministic: a test asserts on exactly how many warnings
			// survive sampling, without sleeping for a refill.
			warnLimiter: logging.NewLimiter(1, 3, time.Minute, func() time.Time { return frozenClock }),
		},
	}

	auditor, err := audit.New(nil, "0.0.0.0:1234", new(server.SecureServingInfo),
		logging.ForComponent(root, logging.ComponentAudit))
	if err != nil {
		t.Fatalf("failed to create auditor: %s", err)
	}
	p.auditor = auditor

	p.handleError = p.newErrorHandler()

	return p
}

// TestRoundTripLogsTokenReviewPassthrough pins the access record on the
// TokenReview passthrough path: the request never reaches impersonation, and
// before this change it produced no record at all.
func TestRoundTripLogsTokenReviewPassthrough(t *testing.T) {
	p := newTestProxy(t)
	p.config = &Config{TokenReview: true}

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(nil, false, errors.New("not an oidc token"))
	p.fakeReviewer.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
		&authenticator.Response{User: &user.DefaultInfo{Name: "system:serviceaccount:default:sa"}}, true, nil)

	handler := p.withHandlers(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if _, err := p.RoundTrip(req); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	}))

	req := withTestRequestID(reservedIdentityRequest(t, nil))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := p.logs.Only(t, logging.EventRequestAccessDecided)
	if got := rec.String("event"); got != "AuSuccess" {
		t.Errorf("event = %q, want AuSuccess", got)
	}
	if got := rec.String("auth_method"); got != string(metrics.AuthMethodTokenReview) {
		t.Errorf("auth_method = %q, want %q", got, metrics.AuthMethodTokenReview)
	}

	p.ctrl.Finish()
}

// withDiscardLoggers gives a Proxy a test built by hand the loggers New would
// have derived, discarding every record, so the never-nil contract on those
// fields holds in tests too. Loggers the test already set are kept.
func withDiscardLoggers(p *Proxy) *Proxy {
	for _, l := range []**slog.Logger{&p.requestLogger, &p.oidcLogger, &p.tokenReviewLogger, &p.upstreamLogger} {
		if *l == nil {
			*l = slog.New(slog.DiscardHandler)
		}
	}
	return p
}
