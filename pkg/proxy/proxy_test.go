// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"bytes"
	stdcontext "context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/mocks"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	proxycontext "github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/hooks"
	accesslogging "github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging"
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
func newAccessLogger(t *testing.T) (*accesslogging.AccessLogger, *logtest.Capture) {
	t.Helper()
	root, records := logtest.New(t, 0)
	return accesslogging.NewAccessLogger(logging.ForComponent(root, logging.ComponentRequest), nil), records
}

// withTestRequestID stamps the correlation id the request-id filter mints in
// production. Every access record is required to carry one.
func withTestRequestID(req *http.Request) *http.Request {
	return proxycontext.WithRequestID(req, "test-request-id")
}

func TestRoundTripperForRestConfigReloadsClientCertificate(t *testing.T) {
	certFile := filepath.Join(t.TempDir(), "client.crt")
	keyFile := filepath.Join(filepath.Dir(certFile), "client.key")
	firstCert, firstKey, err := cert.GenerateSelfSignedCertKey("first-client", nil, nil)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertKey(first-client) error = %v", err)
	}
	secondCert, secondKey, err := cert.GenerateSelfSignedCertKey("second-client", nil, nil)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertKey(second-client) error = %v", err)
	}
	writeProxyClientKeyPair(t, certFile, keyFile, firstCert, firstKey)

	p := &Proxy{}
	roundTripper, err := p.roundTripperForRestConfig(&rest.Config{
		TLSClientConfig: rest.TLSClientConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	})
	if err != nil {
		t.Fatalf("roundTripperForRestConfig() error = %v", err)
	}
	tlsConfig, err := utilnet.TLSClientConfig(roundTripper)
	if err != nil {
		t.Fatalf("TLSClientConfig() error = %v", err)
	}
	if tlsConfig == nil || tlsConfig.GetClientCertificate == nil {
		t.Fatal("roundTripperForRestConfig() has no dynamic client-certificate callback")
	}
	if len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != "http/1.1" {
		t.Errorf("roundTripperForRestConfig() NextProtos = %v, want [http/1.1]", tlsConfig.NextProtos)
	}

	gotFirst, err := tlsConfig.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate(first) error = %v", err)
	}
	writeProxyClientKeyPair(t, certFile, keyFile, secondCert, secondKey)
	time.Sleep(1100 * time.Millisecond)
	gotSecond, err := tlsConfig.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate(second) error = %v", err)
	}
	if bytes.Equal(gotFirst.Certificate[0], gotSecond.Certificate[0]) {
		t.Error("GetClientCertificate() returned the original certificate after files rotated")
	}

	strippedTransport, err := p.roundTripperForRestConfig(&rest.Config{})
	if err != nil {
		t.Fatalf("roundTripperForRestConfig(stripped) error = %v", err)
	}
	strippedTLSConfig, err := utilnet.TLSClientConfig(strippedTransport)
	if err != nil {
		t.Fatalf("TLSClientConfig(stripped) error = %v", err)
	}
	if strippedTLSConfig != nil && strippedTLSConfig.GetClientCertificate != nil {
		t.Error("credential-stripped transport unexpectedly has a client certificate")
	}
}

func writeProxyClientKeyPair(t *testing.T, certFile, keyFile string, certData, keyData []byte) {
	t.Helper()
	if err := os.WriteFile(certFile, certData, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", certFile, err)
	}
	if err := os.WriteFile(keyFile, keyData, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", keyFile, err)
	}
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
	assertDeniedReason(t, records, reasonUnauthorized)

	frw, records = tryError(t, http.StatusForbidden, errNoName)
	if exp := []byte("Username claim not available in OIDC Issuer response\n"); !bytes.Equal(frw.buffer, exp) {
		t.Errorf("unexpected response, exp='%s' got='%s'", exp, frw.buffer)
	}
	assertDeniedReason(t, records, reasonNoUsernameClaim)

	frw, records = tryError(t, http.StatusInternalServerError, errors.New("foo"))
	if exp := []byte("\n"); !bytes.Equal(frw.buffer, exp) {
		t.Errorf("unexpected response, exp='%s' got='%s'", exp, frw.buffer)
	}
	assertDeniedReason(t, records, reasonInternalError)
}

// assertDeniedReason pins the single AuFail record a refusal writes, and the
// closed reason it is classified by.
func assertDeniedReason(t *testing.T, records *logtest.Capture, wantReason string) {
	t.Helper()
	rec := records.Only(t, logging.EventRequestAccessDecided)
	if got := rec.String("event"); got != "AuFail" {
		t.Errorf("event = %q, want AuFail", got)
	}
	if got := rec.String("decision"); got != "deny" {
		t.Errorf("decision = %q, want deny", got)
	}
	if got := rec.String("reason"); got != wantReason {
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
		expReason string
	}{
		"unauthorized": {errUnauthorized, http.StatusUnauthorized, reasonUnauthorized},
		"reserved identity": {fmt.Errorf("%w: username %q", errReservedIdentity, "system:masters"),
			http.StatusForbidden, reasonReservedIdentity},
		"no username claim": {errNoName, http.StatusForbidden, reasonNoUsernameClaim},
		"too many impersonation values": {fmt.Errorf("%w: 5 > 2", subjectaccessreview.ErrTooManyImpersonationHeaderValues),
			http.StatusRequestHeaderFieldsTooLarge, reasonTooManyImpersonationValues},
		"impersonation denied": {&subjectaccessreview.ImpersonationAuthError{
			Requester: "mmosley", Kind: "group", Target: "'system:masters'"},
			http.StatusForbidden, reasonImpersonationDenied},
		"no impersonation config": {errNoImpersonationConfig, http.StatusInternalServerError, reasonInternalError},
		"no impersonation user":   {subjectaccessreview.ErrorNoImpersonationUserFound, http.StatusInternalServerError, reasonInternalError},
		"unknown":                 {errors.New("boom"), http.StatusInternalServerError, reasonInternalError},
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
	assertDeniedReason(t, records, reasonClientCanceled)
}

// TestErrorImpersonationDenialNamesTheTarget pins that the refused target is
// carried as structured fields taken from the typed error, so nobody has to
// parse it back out of the client-facing message.
func TestErrorImpersonationDenialNamesTheTarget(t *testing.T) {
	tests := map[string]struct {
		kind, target         string
		expKind, expTargetNm string
	}{
		"group": {"group", "'system:masters'", "group", "system:masters"},
		"user":  {"user", "'a-user'", "user", "a-user"},
		"uid":   {"uid", "'bar'", "uid", "bar"},
		// "extra info" is how the client-facing message renders it; the record
		// carries the closed target_kind value.
		"extra": {"extra info", "'foo'='bar'", "extra", "foo'='bar"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, records := tryError(t, http.StatusForbidden, &subjectaccessreview.ImpersonationAuthError{
				Requester: "mmosley", Kind: test.kind, Target: test.target,
			})
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

func TestHasImpersonation(t *testing.T) {
	p := new(Proxy)

	// no impersonation headers
	noImpersonation := []http.Header{
		{},
		{
			"foo": []string{"bar", "foo"},
		},
		{
			"impersonation": []string{"bar"},
			"impersonate":   []string{"bar"},
		},
		{
			"Impersonate": []string{"bar", "foo"},
		},

		{
			"-impersonate-Extra-": []string{"bar", "foo"},
		},
		{
			"a": []string{"Impersonate-User"},
			"b": []string{"Impersonate-Group"},
			"c": []string{"Impersonate-Extra-"},
		},
	}

	// impersonation headers
	hasImpersonation := []http.Header{
		{
			"Impersonate-User": []string{"bar", "foo"},
		},
		{
			"impersonate-user": []string{"bar", "foo"},
		},
		{
			"impersonate-user": nil,
		},
		{
			"impersonate-group": nil,
		},
		{
			"impersonate-Group": []string{"bar", "foo"},
		},
		{
			"impersonate-Extra-foobar___foo": []string{"bar", "foo"},
		},
		{
			"impersonate-Extra-": []string{"bar", "foo"},
		},
		{
			"impersonate-Extra-": []string{"bar", "foo"},
			"impersonate-Group":  []string{"bar", "foo"},
			"impersonate-User":   []string{"bar"},
		},
		{
			"impersonate-Extra-": []string{"bar", "foo"},
			"foo":                []string{"bar", "foo"},
			"bar":                []string{"bar"},
		},
		{
			"foo":                []string{"bar", "foo"},
			"impersonate-Extra-": []string{"bar", "foo"},
			"bar":                []string{"bar"},
			"impersonate-Group":  []string{"bar", "foo"},
			"foo2":               []string{"bar", "foo"},
			"impersonate-User":   []string{"bar"},
			"bar2":               []string{"bar"},
		},
		// any attempt to user impersonate- should be interpreted as
		// an impersonation header since it could be in the future
		{
			"impersonate-Extra": []string{"bar", "foo"},
		},
	}

	for _, h := range noImpersonation {
		if p.hasImpersonation(h) {
			t.Errorf("expected no impersonation but got true, '%s'", h)
		}
	}

	for _, h := range hasImpersonation {
		if !p.hasImpersonation(h) {
			t.Errorf("expected impersonation but got false, '%s'", h)
		}
	}
}

func newTestProxy(t *testing.T) *fakeProxy {
	ctrl := gomock.NewController(t)
	fakeToken := mocks.NewMockToken(ctrl)
	fakeReviewer := mocks.NewMockToken(ctrl)
	fakeRT := &fakeRT{t: t}

	// One root, one capture: every component the fake proxy owns writes into
	// the same stream, so a test can assert on any record the request produced
	// through fakeProxy.logs.
	root, logs := logtest.New(t, 2)
	requestLogger := logging.ForComponent(root, logging.ComponentRequest)

	fakeSubjectAccessReviewer := fakesubjectaccessreview.New(nil)
	subjectAccessReview, _ := subjectaccessreview.New(fakeSubjectAccessReviewer, subjectaccessreview.DefaultTimeout, 0, 0,
		subjectaccessreview.DefaultMaxHeaderValues, logging.ForComponent(root, logging.ComponentSAR))

	p := &fakeProxy{
		ctrl:         ctrl,
		fakeToken:    fakeToken,
		fakeReviewer: fakeReviewer,
		fakeRT:       fakeRT,
		logs:         logs,
		Proxy: &Proxy{
			logger:                requestLogger,
			access:                accesslogging.NewAccessLogger(requestLogger, nil),
			oidcRequestAuther:     bearertoken.New(fakeToken),
			tokenReviewer:         fakeReviewer,
			subjectAccessReviewer: subjectAccessReview,
			clientTransport:       fakeRT,
			noAuthClientTransport: fakeRT,
			config:                new(Config),
			hooks:                 hooks.New(logging.ForComponent(root, logging.ComponentShutdown)),
		},
	}

	auditor, err := audit.New(new(options.AuditOptions), "0.0.0.0:1234", new(server.SecureServingInfo),
		logging.ForComponent(root, logging.ComponentAudit))
	if err != nil {
		t.Fatalf("failed to create auditor: %s", err)
	}
	p.auditor = auditor

	p.handleError = p.newErrorHandler()

	return p
}

func TestHandlers(t *testing.T) {
	type authResponse struct {
		resp *authenticator.Response
		pass bool
		err  error
	}

	tests := map[string]struct {
		req    *http.Request
		config *Config

		expAuthToken string
		authResponse *authResponse

		expCode int
		expBody string

		expUser  string
		expGroup []string
		expExtra map[string][]string
		expUID   string

		// expEvent is the access record's event field, expReason its reason
		// (empty on an allow) and expAuthMethod how the request authenticated.
		expEvent      string
		expReason     string
		expAuthMethod string
	}{
		"an empty request should 401": {
			expEvent:      "AuFail",
			expReason:     reasonUnauthorized,
			expAuthMethod: authMethodNone,
			req:           new(http.Request),
			expCode:       http.StatusUnauthorized,
			expBody:       "Unauthorized",
		},
		"a request with a badly formed token should 401": {
			expEvent:      "AuFail",
			expReason:     reasonUnauthorized,
			expAuthMethod: authMethodNone,
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{"foo"},
				},
			},
			expCode: http.StatusUnauthorized,
			expBody: "Unauthorized",
		},
		"a request with a unauthed token should 401": {
			expEvent:      "AuFail",
			expReason:     reasonUnauthorized,
			expAuthMethod: authMethodNone,
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{"bearer fake-token"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: nil,
				pass: false,
				err:  nil,
			},
			expCode: http.StatusUnauthorized,
			expBody: "Unauthorized",
		},
		"a request with an error during token auth should 401": {
			expEvent:      "AuFail",
			expReason:     reasonUnauthorized,
			expAuthMethod: authMethodNone,
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{"bearer fake-token"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: nil,
				pass: false,
				err:  errors.New("some error"),
			},
			expCode: http.StatusUnauthorized,
			expBody: "Unauthorized",
		},
		"a request with an error but passes during token auth should still 401": {
			expEvent:      "AuFail",
			expReason:     reasonUnauthorized,
			expAuthMethod: authMethodNone,
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{"bearer fake-token"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: nil,
				pass: true,
				err:  errors.New("some error"),
			},
			expCode: http.StatusUnauthorized,
			expBody: "Unauthorized",
		},
		"a request with unauth with impersonation should 401": {
			expEvent:      "AuFail",
			expReason:     reasonUnauthorized,
			expAuthMethod: authMethodNone,
			req: &http.Request{
				Header: http.Header{
					"Authorization":    []string{"bearer fake-token"},
					"Impersonate-User": []string{"a-user"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: nil,
				pass: false,
				err:  nil,
			},
			expCode: http.StatusUnauthorized,
			expBody: "Unauthorized",
		},

		// BEGIN IMPERSONATION TESTS

		"an authed request with authorized impersonation user should succeed": {
			expEvent:      "AuSuccess",
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":    []string{"bearer fake-token"},
					"Impersonate-User": []string{"jjackson"},
				},
			},
			expUser:      "jjackson",
			expGroup:     []string{"system:authenticated"},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode: http.StatusOK,
			expExtra: map[string][]string{
				"Impersonate-Extra-Originaluser.jetstack.io-User":   {"mmosley"},
				"Impersonate-Extra-Originaluser.jetstack.io-Groups": {"group1"},
			},
			expBody: "",
		},
		"an authed request with authorized impersonation group should succeed": {
			expEvent:      "AuSuccess",
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":     []string{"bearer fake-token"},
					"Impersonate-User":  []string{"jjackson"},
					"Impersonate-Group": []string{"group3"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
					},
				},
				pass: true,
				err:  nil,
			},
			expUser:  "jjackson",
			expGroup: []string{"group3", "system:authenticated"},
			expExtra: map[string][]string{
				"Impersonate-Extra-Originaluser.jetstack.io-User":   {"mmosley"},
				"Impersonate-Extra-Originaluser.jetstack.io-Groups": {"group1"},
			},
			expCode: http.StatusOK,
			expBody: "",
		},
		"an authed request with authorized impersonation extra should succeed": {
			expEvent:      "AuSuccess",
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":                []string{"bearer fake-token"},
					"Impersonate-User":             []string{"jjackson"},
					"Impersonate-Group":            []string{"group3"},
					"Impersonate-Extra-remoteaddr": []string{"1.2.3.4"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
						Extra:  map[string][]string{"someextra": {"someval1", "someval2"}, "someextra2": {"foo", "bar"}},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode:  http.StatusOK,
			expUser:  "jjackson",
			expGroup: []string{"group3", "system:authenticated"},
			expExtra: map[string][]string{
				"Impersonate-Extra-Remoteaddr":                      {"1.2.3.4"},
				"Impersonate-Extra-Originaluser.jetstack.io-User":   {"mmosley"},
				"Impersonate-Extra-Originaluser.jetstack.io-Groups": {"group1"},
				"Impersonate-Extra-Originaluser.jetstack.io-Extra":  {"{\"someextra\":[\"someval1\",\"someval2\"],\"someextra2\":[\"foo\",\"bar\"]}"},
			},
			expBody: "",
		},

		"an authed request with authorized impersonation extra should succeed, with an empty X-Forwarded-For header": {
			expEvent:      "AuSuccess",
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":                []string{"bearer fake-token"},
					"Impersonate-User":             []string{"jjackson"},
					"Impersonate-Group":            []string{"group3"},
					"Impersonate-Extra-remoteaddr": []string{"1.2.3.4"},
					"X-Forwarded-For":              []string{""},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
						Extra:  map[string][]string{"someextra": {"someval1", "someval2"}, "someextra2": {"foo", "bar"}},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode:  http.StatusOK,
			expUser:  "jjackson",
			expGroup: []string{"group3", "system:authenticated"},
			expExtra: map[string][]string{
				"Impersonate-Extra-Remoteaddr":                      {"1.2.3.4"},
				"Impersonate-Extra-Originaluser.jetstack.io-User":   {"mmosley"},
				"Impersonate-Extra-Originaluser.jetstack.io-Groups": {"group1"},
				"Impersonate-Extra-Originaluser.jetstack.io-Extra":  {"{\"someextra\":[\"someval1\",\"someval2\"],\"someextra2\":[\"foo\",\"bar\"]}"},
			},
			expBody: "",
		},

		"an authed request with authorized impersonation uid should succeed": {
			expEvent:      "AuSuccess",
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":     []string{"bearer fake-token"},
					"Impersonate-Uid":   []string{"1-2-3-4"},
					"Impersonate-User":  []string{"jjackson"},
					"Impersonate-Group": []string{"group3"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode:  http.StatusOK,
			expUser:  "jjackson",
			expUID:   "1-2-3-4",
			expGroup: []string{"group3", "system:authenticated"},
			expExtra: map[string][]string{
				"Impersonate-Extra-Originaluser.jetstack.io-User":   {"mmosley"},
				"Impersonate-Extra-Originaluser.jetstack.io-Groups": {"group1"},
			},
			expBody: "",
		},

		"an authed request with unauthorized impersonation user should error unauthorized": {
			expEvent:      "AuFail",
			expReason:     reasonImpersonationDenied,
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":    []string{"bearer fake-token"},
					"Impersonate-User": []string{"a-user"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode: http.StatusForbidden,
			expBody: "mmosley is not allowed to impersonate user 'a-user'",
		},
		"an authed request with unauthorized impersonation group should error unauthorized": {
			expEvent:      "AuFail",
			expReason:     reasonImpersonationDenied,
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":     []string{"bearer fake-token"},
					"Impersonate-User":  []string{"jjackson"},
					"Impersonate-Group": []string{"a-group"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode: http.StatusForbidden,
			expBody: "mmosley is not allowed to impersonate group 'a-group'",
		},
		"an authed request with unauthorized impersonation extra should error unauthorized": {
			expEvent:      "AuFail",
			expReason:     reasonImpersonationDenied,
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":         []string{"bearer fake-token"},
					"Impersonate-User":      []string{"jjackson"},
					"Impersonate-Extra-foo": []string{"bar"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode: http.StatusForbidden,
			expBody: "mmosley is not allowed to impersonate extra info 'foo'='bar'",
		},
		"an authed request with unauthorized impersonation uid should error unauthorized": {
			expEvent:      "AuFail",
			expReason:     reasonImpersonationDenied,
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":    []string{"bearer fake-token"},
					"Impersonate-User": []string{"jjackson"},
					"Impersonate-Uid":  []string{"bar"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode: http.StatusForbidden,
			expBody: "mmosley is not allowed to impersonate uid 'bar'",
		},

		"an authed request with impersonation groups missing user should fail": {
			expEvent:      "AuFail",
			expReason:     reasonInternalError,
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":      []string{"bearer fake-token"},
					"Impersonate-Groups": []string{"bar"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode: http.StatusInternalServerError,
			expBody: "no Impersonation-User header found for request",
		},

		"an authed request with impersonation extra missing user should fail": {
			expEvent:      "AuFail",
			expReason:     reasonInternalError,
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":         []string{"bearer fake-token"},
					"Impersonate-Extra-foo": []string{"bar"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode: http.StatusInternalServerError,
			expBody: "no Impersonation-User header found for request",
		},

		"an authed request with impersonation uid missing user should fail": {
			expEvent:      "AuFail",
			expReason:     reasonInternalError,
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":   []string{"bearer fake-token"},
					"Impersonate-Uid": []string{"bar"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode: http.StatusInternalServerError,
			expBody: "no Impersonation-User header found for request",
		},

		"an authed request with an invalid impersonation header should fail": {
			expEvent:      "AuFail",
			expReason:     reasonInternalError,
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":        []string{"bearer fake-token"},
					"Impersonate-User":     []string{"jjackson"},
					"Impersonate-Not-Real": []string{"bar"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "mmosley",
						Groups: []string{"group1"},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode: http.StatusInternalServerError,
			expBody: "",
		},

		// END IMPERSONATION TESTS

		"an authed request with no username is token should 403": {
			expEvent:      "AuFail",
			expReason:     reasonNoUsernameClaim,
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{"bearer fake-token"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{Name: ""},
				},
				pass: true,
				err:  nil,
			},
			expCode: http.StatusForbidden,
			expBody: "Username claim not available in OIDC Issuer response",
		},
		"an authed request with user should 200": {
			expEvent:      "AuSuccess",
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{"bearer fake-token"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{Name: "a-user"},
				},
				pass: true,
				err:  nil,
			},
			expCode:  http.StatusOK,
			expBody:  "",
			expUser:  "a-user",
			expGroup: []string{"system:authenticated"},
		},
		"an authed request with user, group, extra should 200": {
			expEvent:      "AuSuccess",
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{"bearer fake-token"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "a-user",
						Groups: []string{"my-group"},
						Extra: map[string][]string{
							"foo":     {"a", "b"},
							"bar":     {"c", "d"},
							"foo-bar": {"e", "f"},
						},
					},
				},
				pass: true,
				err:  nil,
			},
			expCode:  http.StatusOK,
			expBody:  "",
			expUser:  "a-user",
			expGroup: []string{"my-group", "system:authenticated"},
			expExtra: map[string][]string{
				"Impersonate-Extra-Foo":     {"a", "b"},
				"Impersonate-Extra-Bar":     {"c", "d"},
				"Impersonate-Extra-Foo-Bar": {"e", "f"},
			},
		},
		"an authed request with user, group, extra but disabled impersonation should return no impersonation and should 200": {
			expEvent:      "AuSuccess",
			expAuthMethod: authMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{"bearer fake-token"},
				},
			},
			expAuthToken: "fake-token",
			authResponse: &authResponse{
				resp: &authenticator.Response{
					User: &user.DefaultInfo{
						Name:   "a-user",
						Groups: []string{"my-group"},
						Extra: map[string][]string{
							"foo":     {"a", "b"},
							"bar":     {"c", "d"},
							"foo-bar": {"e", "f"},
						},
					},
				},
				pass: true,
				err:  nil,
			},
			config: &Config{
				DisableImpersonation: true,
			},
			expCode:  http.StatusOK,
			expBody:  "",
			expUser:  "",
			expGroup: nil,
			expExtra: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)

			w := httptest.NewRecorder()

			if test.authResponse != nil {
				p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), test.expAuthToken).Return(
					test.authResponse.resp, test.authResponse.pass, test.authResponse.err)
			}

			p.fakeRT.expUser = test.expUser
			p.fakeRT.expGroup = test.expGroup
			p.fakeRT.expExtra = test.expExtra
			p.fakeRT.expUID = test.expUID

			if test.config != nil {
				p.config = test.config
			}

			var handler http.Handler
			handler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				_, err := p.RoundTrip(req)
				if err != nil {
					t.Errorf("unexpected error: %s", err)
					t.FailNow()
				}
			})

			// Fill in the method, path, peer and header map a served request
			// always has; the request-id filter is the outermost handler in
			// this chain, so it mints the correlation id itself.
			test.req.URL = &url.URL{Path: "/api/v1/pods"}
			if test.req.Method == "" {
				test.req.Method = http.MethodGet
			}
			if test.req.RemoteAddr == "" {
				test.req.RemoteAddr = "1.2.3.4:5555"
			}
			if test.req.Header == nil {
				test.req.Header = make(http.Header)
			}

			handler = p.withHandlers(handler)
			handler.ServeHTTP(w, test.req)

			resp := w.Result()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				t.FailNow()
			}

			if test.expBody != strings.TrimSpace(string(body)) {
				t.Errorf("got unexpected response body, exp=%s got=%s",
					test.expBody, body)
			}

			if test.expCode != resp.StatusCode {
				t.Errorf("got unexpected response code, exp=%d got=%d",
					test.expCode, resp.StatusCode)
			}

			// Exactly one access record per request, carrying the outcome, the
			// classified reason and how the request authenticated.
			rec := p.logs.Only(t, logging.EventRequestAccessDecided)
			if got := rec.String("event"); got != test.expEvent {
				t.Errorf("event = %q, want %q", got, test.expEvent)
			}
			if got := rec.String("reason"); got != test.expReason {
				t.Errorf("reason = %q, want %q", got, test.expReason)
			}
			if got := rec.String("auth_method"); got != test.expAuthMethod {
				t.Errorf("auth_method = %q, want %q", got, test.expAuthMethod)
			}
			// The id is the one the filter minted, not one the test stamped:
			// the whole chain now runs behind withRequestID.
			if got := rec.String("request_id"); !uuidRE.MatchString(got) {
				t.Errorf("request_id = %q, want a minted UUID", got)
			}

			p.ctrl.Finish()
		})
	}
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
	if got := rec.String("auth_method"); got != authMethodTokenReview {
		t.Errorf("auth_method = %q, want %q", got, authMethodTokenReview)
	}

	p.ctrl.Finish()
}

func TestHeadersConfig(t *testing.T) {
	remoteAddr := "8.8.8.8"

	tests := map[string]struct {
		config   *Config
		expExtra map[string][]string
	}{
		"if no extra headers set or client IP enabled then expect no extras": {
			config: &Config{
				ExtraUserHeaders:                nil,
				ExtraUserHeadersClientIPEnabled: false,
			},
			expExtra: nil,
		},
		"if extra headers set but no client IP enabled then should return added extras": {
			config: &Config{
				ExtraUserHeaders: map[string][]string{
					"foo": {"a", "b"},
					"bar": {"c", "d", "e"},
				},
				ExtraUserHeadersClientIPEnabled: false,
			},
			expExtra: map[string][]string{
				"Impersonate-Extra-Foo": {"a", "b"},
				"Impersonate-Extra-Bar": {"c", "d", "e"},
			},
		},
		"if no extra headers set but client IP enabled then should return added client IP": {
			config: &Config{
				ExtraUserHeaders:                nil,
				ExtraUserHeadersClientIPEnabled: true,
			},
			expExtra: map[string][]string{
				"Impersonate-Extra-Remote-Client-Ip": {"8.8.8.8"},
			},
		},
		"if extra headers set and client IP enabled then should return extra headers and client IP": {
			config: &Config{
				ExtraUserHeaders: map[string][]string{
					"foo": {"a", "b"},
					"bar": {"c", "d", "e"},
				},
				ExtraUserHeadersClientIPEnabled: true,
			},
			expExtra: map[string][]string{
				"Impersonate-Extra-Foo":              {"a", "b"},
				"Impersonate-Extra-Bar":              {"c", "d", "e"},
				"Impersonate-Extra-Remote-Client-Ip": {"8.8.8.8"},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)

			p.config = test.config
			w := httptest.NewRecorder()

			req := withTestRequestID(&http.Request{
				Method: http.MethodGet,
				Header: http.Header{
					"Authorization": []string{"bearer fake-token"},
				},
				RemoteAddr: remoteAddr,
				URL:        &url.URL{Path: "/api/v1/pods"},
			})

			authResponse := &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   "a-user",
					Groups: []string{user.AllAuthenticated},
				},
			}

			p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(authResponse, true, nil)

			p.fakeRT.expUser = "a-user"
			p.fakeRT.expGroup = []string{user.AllAuthenticated}
			p.fakeRT.expExtra = test.expExtra

			var handler http.Handler
			handler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				_, err := p.RoundTrip(req)
				if err != nil {
					t.Errorf("unexpected error: %s", err)
					t.FailNow()
				}
			})

			handler = p.withHandlers(handler)
			handler.ServeHTTP(w, req)

			w.Result()

			p.ctrl.Finish()
		})
	}
}

func TestParseAllowedReservedGroups(t *testing.T) {
	tests := map[string]struct {
		groups  []string
		wantErr bool
	}{
		"empty is allowed":        {groups: nil},
		"reserved group":          {groups: []string{"system:monitoring"}},
		"several reserved groups": {groups: []string{"system:monitoring", "system:logging"}},
		// Listing a group that was never going to be refused is a no-op, so it
		// is almost certainly a typo in a security-relevant setting.
		"unreserved group is rejected": {groups: []string{"monitoring"}, wantErr: true},
		"empty entry is rejected":      {groups: []string{"system:monitoring", " "}, wantErr: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseAllowedReservedGroups(test.groups)

			if test.wantErr {
				if err == nil {
					t.Fatalf("parseAllowedReservedGroups(%q) = nil error, want an error", test.groups)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAllowedReservedGroups(%q) error = %v, want nil", test.groups, err)
			}
			if got.Len() != len(test.groups) {
				t.Errorf("parseAllowedReservedGroups(%q) has %d entries, want %d", test.groups, got.Len(), len(test.groups))
			}
		})
	}
}

// TestReviewTokenRejectedIsNotLoggedAsValid pins the token-review denial
// message: an unauthenticated review result is a rejection, and reporting it as
// a valid token passing through misleads anyone reading the log during an
// incident.
func TestReviewTokenRejectedIsNotLoggedAsValid(t *testing.T) {
	buf := captureKlogAtV2(t)
	var fs flag.FlagSet
	klog.InitFlags(&fs)
	_ = fs.Set("v", "4")
	t.Cleanup(func() { _ = fs.Set("v", "2") })

	p := newTestProxy(t)
	p.fakeReviewer.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(nil, false, nil)

	req := reservedIdentityRequest(t, nil)
	if ok := p.reviewToken(httptest.NewRecorder(), req); ok {
		t.Fatal("rejected token reported as passthrough-ok")
	}
	klog.Flush()
	if strings.Contains(buf.String(), "valid token") {
		t.Fatalf("rejected token logged as valid:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "rejected") {
		t.Fatalf("rejected token not logged as rejected:\n%s", buf.String())
	}
}
