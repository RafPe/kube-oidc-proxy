// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	stdcontext "context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/authn/authntest"
	"github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview"
	fakesubjectaccessreview "github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview/fake"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
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

	if exp, act := f.expGroup, h.Header["Impersonate-Group"]; !reflect.DeepEqual(exp, act) {
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

// newTestAuditor builds an auditor with no backend, as the binary does when
// no audit flag is set, so every audit filter is still in the chain. audit.New
// needs an external address when there is no listener to derive one from.
func newTestAuditor(t *testing.T, root *slog.Logger) *audit.Audit {
	t.Helper()
	auditor, err := audit.New(audit.Config{ExternalAddress: "0.0.0.0:1234"},
		logging.ForComponent(root, logging.ComponentAudit))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	return auditor
}

// newArgs is what newTestProxy passes to New, gathered so an option can adjust
// any of it.
type newArgs struct {
	cfg  Config
	deps Dependencies
	root *slog.Logger
}

// newTestProxy builds a Proxy through New, from fakes: a mock OIDC
// authenticator and token reviewer, a SubjectAccessReview over the fake
// review client, a real metrics recorder and one log capture. opts adjust the
// arguments before New sees them, so a test that needs a different
// configuration or authorizer gets it wired the way the binary wires it.
func newTestProxy(t *testing.T, opts ...func(*newArgs)) *fakeProxy {
	t.Helper()

	ctrl := gomock.NewController(t)
	fakeToken := authntest.NewMockToken(ctrl)
	fakeReviewer := authntest.NewMockToken(ctrl)
	fakeRT := &fakeRT{t: t}

	// One root, one capture: every component the proxy owns writes into the
	// same stream, so a test can assert on any record the request produced
	// through fakeProxy.logs.
	root, logs := logtest.New(t, 2)
	trackCapture(logs)

	sar := subjectaccessreview.New(fakesubjectaccessreview.New(nil),
		subjectaccessreview.Config{MaxHeaderValues: subjectaccessreview.DefaultMaxHeaderValues},
		logging.ForComponent(root, logging.ComponentSAR))

	// A real recorder, not a fake: the tests assert on the exposition the
	// binary would serve, including help strings and label names.
	recorder, err := metrics.New(metrics.BuildInfo{Version: "test", Revision: "test", GoVersion: "test"})
	if err != nil {
		t.Fatalf("metrics.New: %v", err)
	}

	args := newArgs{
		deps: Dependencies{
			RestConfig:              &rest.Config{Host: "https://kube.example.com"},
			OIDCTokenAuthenticator:  fakeToken,
			TokenReviewer:           fakeReviewer,
			ImpersonationAuthorizer: sar,
			SecureServingInfo:       new(server.SecureServingInfo),
			Auditor:                 newTestAuditor(t, root),
			Metrics:                 recorder,
		},
		root: root,
	}
	for _, opt := range opts {
		opt(&args)
	}

	p, err := New(args.cfg, args.deps, args.root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The only fields set after New, because New cannot produce them. It
	// builds real transports from RestConfig, and these tests assert on what
	// would reach the API server instead of sending it. Its limiter runs on
	// the wall clock; a frozen clock and a small burst let a test count
	// exactly how many warnings survive sampling without sleeping for a refill.
	p.clientTransport = fakeRT
	p.noAuthClientTransport = fakeRT
	p.warnLimiter = logging.NewLimiter(1, 3, time.Minute, func() time.Time { return frozenClock })

	return &fakeProxy{
		ctrl:         ctrl,
		fakeToken:    fakeToken,
		fakeReviewer: fakeReviewer,
		fakeRT:       fakeRT,
		logs:         logs,
		Proxy:        p,
	}
}

// withConfig has newTestProxy build the proxy from cfg, so New derives what
// it derives from a Config (the parsed trusted proxies and reserved-group
// allowlist, the transport for unimpersonated requests) exactly as it does in
// production.
func withConfig(cfg Config) func(*newArgs) {
	return func(a *newArgs) {
		a.cfg = cfg
	}
}

// withLogger has newTestProxy build the proxy on root instead of its own
// capture, for a test that needs a different verbosity.
func withLogger(root *slog.Logger) func(*newArgs) {
	return func(a *newArgs) {
		a.root = root
	}
}

// withImpersonationAuthorizer has newTestProxy wire sar in place of its
// default authorizer.
func withImpersonationAuthorizer(sar *subjectaccessreview.Authorizer) func(*newArgs) {
	return func(a *newArgs) {
		a.deps.ImpersonationAuthorizer = sar
	}
}

// TestRoundTripLogsTokenReviewPassthrough pins the access record on the
// TokenReview passthrough path: the request never reaches impersonation, so
// roundTrip is the only place its admission is recorded.
func TestRoundTripLogsTokenReviewPassthrough(t *testing.T) {
	p := newTestProxy(t, withConfig(Config{TokenPassthrough: true}))

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(nil, false, errors.New("not an oidc token"))
	p.fakeReviewer.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
		&authenticator.Response{User: &user.DefaultInfo{Name: "system:serviceaccount:default:sa"}}, true, nil)

	handler := p.withFilterChain(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if _, err := p.roundTrip(req); err != nil {
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

// TestReverseProxyWiring pins the handler Start serves at the bottom of the
// filter chain: its transport is roundTrip and its failures go to
// handleUpstreamError (a request with no forwarding decision reaches the
// first and is answered 500 by the second), it flushes at the configured
// interval, and what it only logs arrives as a WARN on the upstream component.
// The ErrorLog record carries no event_type, so it is written to a capture of
// its own rather than the one the package sweep holds to the registry.
func TestReverseProxyWiring(t *testing.T) {
	root, logs := logtest.New(t, 0)
	p := newTestProxy(t, withConfig(Config{FlushInterval: 250 * time.Millisecond}), withLogger(root))

	rp, err := p.reverseProxy()
	if err != nil {
		t.Fatalf("reverseProxy: %v", err)
	}
	if rp.FlushInterval != 250*time.Millisecond {
		t.Errorf("FlushInterval = %v, want 250ms", rp.FlushInterval)
	}

	rw := httptest.NewRecorder()
	rp.ServeHTTP(rw, withTestRequestID(httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)))
	if rw.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rw.Code)
	}
	if got := logs.Only(t, logging.EventRequestHandlerFailed).String("error_message"); !strings.Contains(got, errNoImpersonationConfig.Error()) {
		t.Errorf("request.handler.failed error_message = %q, want it to name %q", got, errNoImpersonationConfig)
	}

	rp.ErrorLog.Print("httputil: ReverseProxy read error during body copy")
	var found bool
	for _, r := range logs.Records() {
		if strings.Contains(r.String("msg"), "body copy") {
			found = true
			if r.String("component") != string(logging.ComponentUpstream) || r.String("level") != "WARN" {
				t.Errorf("ErrorLog record = %v, want component=upstream level=WARN", r)
			}
		}
	}
	if !found {
		t.Errorf("ErrorLog wrote no record: %s", logs.Raw())
	}
}

// TestReverseProxyRejectsUnparseableHost pins that a malformed API server URL
// fails Start before anything is served.
func TestReverseProxyRejectsUnparseableHost(t *testing.T) {
	p := newTestProxy(t)
	p.restConfig = &rest.Config{Host: "https://kube.example.com/%zz"}
	if _, err := p.reverseProxy(); err == nil {
		t.Fatal("reverseProxy accepted an unparseable host")
	}
}

// TestWaitBeforeStartReturns pins that a Proxy that never served has nothing to
// wait for.
func TestWaitBeforeStartReturns(t *testing.T) {
	newTestProxy(t).Wait()
}
