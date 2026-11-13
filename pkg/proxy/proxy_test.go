// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	stdcontext "context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/server"
	apiserveroptions "k8s.io/apiserver/pkg/server/options"
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

// testIssuerName is the issuer every accepted token is attributed to:
// newTestProxy wraps the fake OIDC authenticator in authn.AttributeToIssuer,
// as authn.Build wraps every configured issuer's authenticator.
// authn.oidc.succeeded requires a non-empty issuer_name.
const testIssuerName = "corp"

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
			OIDCTokenAuthenticator:  authn.AttributeToIssuer(testIssuerName, fakeToken),
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
	p.proxyCredentialTransport = fakeRT
	p.noProxyCredentialTransport = fakeRT
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
	// The identity TokenReview returned is who the record names.
	if got := rec.String("inbound_user"); got != "system:serviceaccount:default:sa" {
		t.Errorf("inbound_user = %q, want the TokenReview identity", got)
	}

	p.ctrl.Finish()
}

// TestTokenReviewPassthroughAuditsTheReviewedIdentity pins that a passthrough
// request is audited as the identity TokenReview returned, as an OIDC request
// is audited as its claims' identity, while what is forwarded is unchanged:
// the client's own token and no impersonation.
func TestTokenReviewPassthroughAuditsTheReviewedIdentity(t *testing.T) {
	auditor, auditLog := newFileAuditor(t)
	p := newTestProxy(t, withConfig(Config{TokenPassthrough: true}), func(a *newArgs) { a.deps.Auditor = auditor })

	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(nil, false, errors.New("not an oidc token"))
	p.fakeReviewer.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
		&authenticator.Response{User: &user.DefaultInfo{
			Name:   "system:serviceaccount:default:sa",
			Groups: []string{"system:serviceaccounts"},
		}}, true, nil)

	var forwarded *http.Request
	p.proxyCredentialTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Error("a passthrough request went out on the proxy's own credentials")
		return nil, errors.New("unexpected")
	})
	p.noProxyCredentialTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		forwarded = req
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
	})

	handler := p.withFilterChain(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if _, err := p.roundTrip(req); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		rw.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), withTestRequestID(reservedIdentityRequest(t, nil)))

	if forwarded == nil {
		t.Fatal("the request was not forwarded")
	}
	if got := forwarded.Header.Get("Authorization"); got != "bearer fake-token" {
		t.Errorf("forwarded Authorization = %q, want the client's own token", got)
	}
	for k := range forwarded.Header {
		if strings.HasPrefix(k, "Impersonate-") {
			t.Errorf("passthrough request carries %s", k)
		}
	}

	events := readAuditEvents(t, auditor, auditLog)
	if len(events) == 0 {
		t.Fatal("no audit event was written")
	}
	for _, event := range events {
		if event.User.Username != "system:serviceaccount:default:sa" {
			t.Errorf("audit event %s user = %q, want the TokenReview identity", event.Stage, event.User.Username)
		}
		if !reflect.DeepEqual(event.User.Groups, []string{"system:serviceaccounts"}) {
			t.Errorf("audit event %s groups = %v, want the TokenReview groups", event.Stage, event.User.Groups)
		}
	}
}

// auditEvent is the subset of an audit.k8s.io/v1 Event the tests assert on.
type auditEvent struct {
	Stage string `json:"stage"`
	User  struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"user"`
}

// newFileAuditor builds a started auditor that writes every stage but
// RequestReceived of every request to a log file at Metadata level, and
// returns it with the file's path.
func newFileAuditor(t *testing.T) (*audit.Audit, string) {
	t.Helper()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	policy := "apiVersion: audit.k8s.io/v1\nkind: Policy\nomitStages: [RequestReceived]\nrules:\n  - level: Metadata\n"
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatalf("writing audit policy: %v", err)
	}

	opts := apiserveroptions.NewAuditOptions()
	opts.PolicyFile = policyPath
	opts.LogOptions.Path = filepath.Join(dir, "audit.log")

	auditor, err := audit.New(audit.Config{Options: opts, ExternalAddress: "0.0.0.0:1234"}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	ctx, cancel := stdcontext.WithCancel(stdcontext.Background())
	t.Cleanup(cancel)
	if err := auditor.Start(ctx); err != nil {
		t.Fatalf("starting audit backend: %v", err)
	}
	return auditor, opts.LogOptions.Path
}

// readAuditEvents flushes the auditor and decodes every event it wrote.
func readAuditEvents(t *testing.T, auditor *audit.Audit, path string) []auditEvent {
	t.Helper()

	auditor.Shutdown()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	var events []auditEvent
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var event auditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decoding audit event %q: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}

// TestRoundTripRefusesAnUnusableForwardDecision pins that roundTrip checks
// the decision it is about to act on, rather than dereferencing an outbound
// identity that is not there, and does so before the access record: a request
// it cannot forward is not recorded as allowed.
func TestRoundTripRefusesAnUnusableForwardDecision(t *testing.T) {
	tests := map[string]*reqctx.ForwardDecisionRecord{
		"impersonating without an outbound identity": {Mode: reqctx.ForwardImpersonating},
		"unknown mode": {Mode: "teleport"},
	}

	for name, fd := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)
			req := reqctx.WithDecisionHolder(withTestRequestID(httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)))

			if _, err := p.roundTrip(reqctx.WithForwardDecision(req, fd)); !errors.Is(err, errInvalidForwardDecision) {
				t.Errorf("roundTrip error = %v, want errInvalidForwardDecision", err)
			}
			if reqctx.DecisionRecorded(req) {
				t.Errorf("an unforwardable request was recorded as allowed: %s", p.logs.Raw())
			}
		})
	}
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
	if got := logs.Only(t, logging.EventRequestHandlerFailed).String("error_message"); !strings.Contains(got, errNoForwardDecision.Error()) {
		t.Errorf("request.handler.failed error_message = %q, want it to name %q", got, errNoForwardDecision)
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
