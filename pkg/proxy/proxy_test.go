// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	stdcontext "context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/authn/authntest"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/accesslog"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	fakesubjectaccessreview "github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview/fake"
)

type fakeProxy struct {
	ctrl *gomock.Controller

	fakeToken    *authntest.MockToken
	fakeReviewer *authntest.MockToken
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
	fakeToken := authntest.NewMockToken(ctrl)
	fakeReviewer := authntest.NewMockToken(ctrl)
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
			shutdownLogger:           logging.ForComponent(root, logging.ComponentShutdown),
			// A frozen clock and a small burst make the warning limiter
			// deterministic: a test asserts on exactly how many warnings
			// survive sampling, without sleeping for a refill.
			warnLimiter: logging.NewLimiter(1, 3, time.Minute, func() time.Time { return frozenClock }),
		},
	}

	auditor, err := audit.New(audit.Config{ExternalAddress: "0.0.0.0:1234", SecureServing: new(server.SecureServingInfo)}, logging.ForComponent(root, logging.ComponentAudit))
	if err != nil {
		t.Fatalf("failed to create auditor: %s", err)
	}
	p.auditor = auditor

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

// TestShutdownReportsTheAuditFlushAsAHook pins the pre-shutdown record: one
// proxy.hook.completed naming the audit backend step, with its duration.
func TestShutdownReportsTheAuditFlushAsAHook(t *testing.T) {
	p := newTestProxy(t)

	if err := p.Shutdown(); err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}

	rec := p.logs.Only(t, logging.EventProxyHookCompleted)
	if got := rec.String("hook"); got != "AuditBackend" {
		t.Errorf("hook = %q, want AuditBackend", got)
	}
	if got := rec.String("component"); got != string(logging.ComponentShutdown) {
		t.Errorf("component = %q, want shutdown", got)
	}
}

// TestWaitBeforeStartReturns pins that a Proxy that never served has nothing to
// wait for.
func TestWaitBeforeStartReturns(t *testing.T) {
	newTestProxy(t).Wait()
}

// sweep collects every capture a test in this package built through
// newTestProxy. Holding them all at the end catches an unregistered event, a
// wrong component or level and a missing required attribute in whatever record
// any test happened to produce, without every test having to assert it.
var sweep struct {
	mu       sync.Mutex
	captures []*logtest.Capture
}

// trackCapture adds a capture to the package sweep. It is called from
// newTestProxy, so tests running in parallel append concurrently.
func trackCapture(c *logtest.Capture) {
	sweep.mu.Lock()
	defer sweep.mu.Unlock()
	sweep.captures = append(sweep.captures, c)
}

// TestMain runs the package's tests and then holds every record they emitted
// against the event registry. It runs after m.Run so the captures are complete.
func TestMain(m *testing.M) {
	code := m.Run()

	tb := new(sweepTB)
	sweep.mu.Lock()
	for _, c := range sweep.captures {
		logtest.AssertRegistered(tb, c)
	}
	sweep.mu.Unlock()

	if tb.failed && code == 0 {
		code = 1
	}
	os.Exit(code)
}

// sweepTB is the testing.TB AssertRegistered reports through when there is no
// *testing.T to report through, which is the case inside TestMain. The
// embedded interface stays nil: every method the assertion uses is overridden
// below, and a call to any other one is a programming error worth the panic.
type sweepTB struct {
	testing.TB
	failed bool
}

func (s *sweepTB) Helper() {}

func (s *sweepTB) Errorf(format string, args ...any) {
	s.failed = true
	fmt.Fprintf(os.Stderr, "events sweep: "+format+"\n", args...)
}

func (s *sweepTB) Error(args ...any) {
	s.Errorf("%s", fmt.Sprint(args...))
}

func (s *sweepTB) Fatalf(format string, args ...any) {
	s.Errorf(format, args...)
}

func (s *sweepTB) Fatal(args ...any) {
	s.Error(args...)
}

// validDeps returns a Dependencies value with every required field populated,
// so individual tests can null out one field to exercise validation.
func validDeps(t *testing.T) Dependencies {
	t.Helper()

	ctrl := gomock.NewController(t)
	root, _ := logtest.New(t, 0)

	sar, err := subjectaccessreview.New(fakesubjectaccessreview.New(nil), subjectaccessreview.Config{Timeout: subjectaccessreview.DefaultTimeout, AllowCacheTTL: 0, DenyCacheTTL: 0, MaxHeaderValues: subjectaccessreview.DefaultMaxHeaderValues}, logging.ForComponent(root, logging.ComponentSAR))
	if err != nil {
		t.Fatalf("building SubjectAccessReview: %v", err)
	}

	return Dependencies{
		Logger:                 root,
		RestConfig:             &rest.Config{Host: "https://kube.example.com"},
		OIDCTokenAuthenticator: authntest.NewMockToken(ctrl),
		AuditOptions:           nil,
		SubjectAccessReviewer:  sar,
		SecureServingInfo:      new(server.SecureServingInfo),
		// ExternalAddress must be set: audit.New derives the audit server's
		// external address from it and fatals when it is empty with no listener.
		Config: &Config{ExternalAddress: "0.0.0.0:1234"},
	}
}

// TestNewRequiresLogger pins that the root logger is a required dependency:
// there is no package-level logger to fall back on, so a caller that forgets to
// inject one must fail at construction rather than emit nothing at runtime.
func TestNewRequiresLogger(t *testing.T) {
	deps := validDeps(t)
	deps.Logger = nil
	if _, err := New(deps); err == nil || !strings.Contains(err.Error(), "Logger is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewValidatesDependencies(t *testing.T) {
	tests := map[string]struct {
		mutate  func(d *Dependencies)
		wantErr bool
	}{
		"valid dependencies succeed": {
			mutate:  func(d *Dependencies) {},
			wantErr: false,
		},
		"nil RestConfig fails": {
			mutate:  func(d *Dependencies) { d.RestConfig = nil },
			wantErr: true,
		},
		"nil OIDCTokenAuthenticator fails": {
			mutate:  func(d *Dependencies) { d.OIDCTokenAuthenticator = nil },
			wantErr: true,
		},
		"nil SubjectAccessReviewer fails": {
			mutate:  func(d *Dependencies) { d.SubjectAccessReviewer = nil },
			wantErr: true,
		},
		"nil SecureServingInfo fails": {
			mutate:  func(d *Dependencies) { d.SecureServingInfo = nil },
			wantErr: true,
		},
		"nil Config fails": {
			mutate:  func(d *Dependencies) { d.Config = nil },
			wantErr: true,
		},
		"TokenReview enabled without reviewer fails": {
			mutate: func(d *Dependencies) {
				d.Config = &Config{TokenReview: true, ExternalAddress: "0.0.0.0:1234"}
				d.TokenReviewer = nil
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			deps := validDeps(t)
			tc.mutate(&deps)

			p, err := New(deps)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("New(%s): expected an error, got nil", name)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%s): unexpected error: %v", name, err)
			}
			if p == nil {
				t.Fatalf("New(%s): expected a Proxy, got nil", name)
			}
		})
	}
}

// TestNewCopiesExtraUserHeaders verifies New copies the caller's Config and its
// ExtraUserHeaders map at the construction boundary, so mutating the caller's
// map afterward cannot change proxy behavior.
func TestNewCopiesExtraUserHeaders(t *testing.T) {
	deps := validDeps(t)
	src := map[string][]string{"team": {"platform"}}
	deps.Config = &Config{ExtraUserHeaders: src, ExternalAddress: "0.0.0.0:1234"}

	p, err := New(deps)
	if err != nil {
		t.Fatalf("New returned unexpected error: %v", err)
	}

	// Mutate the caller-owned map and slice after construction.
	src["team"][0] = "mutated"
	src["injected"] = []string{"value"}

	got := p.config.ExtraUserHeaders
	if v := got["team"][0]; v != "platform" {
		t.Fatalf("proxy shares slice storage with caller: got %q want %q", v, "platform")
	}
	if _, ok := got["injected"]; ok {
		t.Fatal("proxy shares map storage with caller: injected key leaked into proxy config")
	}
}
