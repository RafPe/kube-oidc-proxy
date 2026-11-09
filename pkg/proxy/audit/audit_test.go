// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/audit"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server"
	apiserveroptions "k8s.io/apiserver/pkg/server/options"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

// TestLongRunningRequests pins the set of requests the audit filter treats as
// long-running. Everything this proxy forwards goes to a kube-apiserver, so the
// streaming subresources must be recorded when the response starts, not only
// when the stream finally ends.
func TestLongRunningRequests(t *testing.T) {
	tests := map[string]struct {
		info *request.RequestInfo
		want bool
	}{
		"watch pods": {
			info: &request.RequestInfo{
				IsResourceRequest: true,
				Verb:              "watch",
				Resource:          "pods",
			},
			want: true,
		},
		"exec into a pod": {
			info: &request.RequestInfo{
				IsResourceRequest: true,
				Verb:              "get",
				Resource:          "pods",
				Subresource:       "exec",
			},
			want: true,
		},
		"attach to a pod": {
			info: &request.RequestInfo{
				IsResourceRequest: true,
				Verb:              "get",
				Resource:          "pods",
				Subresource:       "attach",
			},
			want: true,
		},
		"port forward to a pod": {
			info: &request.RequestInfo{
				IsResourceRequest: true,
				Verb:              "get",
				Resource:          "pods",
				Subresource:       "portforward",
			},
			want: true,
		},
		"follow pod logs": {
			info: &request.RequestInfo{
				IsResourceRequest: true,
				Verb:              "get",
				Resource:          "pods",
				Subresource:       "log",
			},
			want: true,
		},
		"service proxy": {
			info: &request.RequestInfo{
				IsResourceRequest: true,
				Verb:              "get",
				Resource:          "services",
				Subresource:       "proxy",
			},
			want: true,
		},
		// The proxy verb allows no subresource, so the verb alone has to carry
		// the decision. See the legacy path case in TestRequestInfoLongRunning
		// for the URL form that produces it.
		"proxy verb": {
			info: &request.RequestInfo{
				IsResourceRequest: true,
				Verb:              "proxy",
				Resource:          "services",
			},
			want: true,
		},
		"get pods": {
			info: &request.RequestInfo{
				IsResourceRequest: true,
				Verb:              "get",
				Resource:          "pods",
			},
			want: false,
		},
		"list pods": {
			info: &request.RequestInfo{
				IsResourceRequest: true,
				Verb:              "list",
				Resource:          "pods",
			},
			want: false,
		},
		"create pods": {
			info: &request.RequestInfo{
				IsResourceRequest: true,
				Verb:              "create",
				Resource:          "pods",
			},
			want: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			if got := longRunningRequests(req, test.info); got != test.want {
				t.Errorf("longRunningRequests(%+v) = %t, want %t", test.info, got, test.want)
			}
		})
	}
}

// TestRequestInfoLongRunning drives real request URLs through the RequestInfo
// resolver that New builds, rather than a hand written RequestInfo. The
// distinction matters: the resolver is what decides whether a URL is a resource
// request at all, and a request it does not recognise arrives at the check
// above with no subresource and the bare HTTP method as its verb, so the check
// can only ever answer false however its sets are written. Everything under
// /api — the core group, where every long-running pod subresource lives — is
// exactly such a request unless the server config names the legacy prefix.
func TestRequestInfoLongRunning(t *testing.T) {
	// An external address with a port, since without one Complete() insists on
	// deriving the port from a secure serving info this test has no use for.
	auditor, err := New(Config{Options: apiserveroptions.NewAuditOptions(), ExternalAddress: "127.0.0.1:6443", SecureServing: nil}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("failed to create auditor: %s", err)
	}

	resolver := auditor.serverConfig.RequestInfoResolver

	tests := map[string]struct {
		method          string
		url             string
		wantVerb        string
		wantResource    string
		wantName        string
		wantSubresource string
		wantLongRunning bool
	}{
		"exec into a pod": {
			method:          http.MethodPost,
			url:             "/api/v1/namespaces/ns-1/pods/pod-1/exec?command=sh&container=c-1&stdout=true",
			wantVerb:        "create",
			wantResource:    "pods",
			wantName:        "pod-1",
			wantSubresource: "exec",
			wantLongRunning: true,
		},
		"attach to a pod": {
			method:          http.MethodPost,
			url:             "/api/v1/namespaces/ns-1/pods/pod-1/attach?container=c-1",
			wantVerb:        "create",
			wantResource:    "pods",
			wantName:        "pod-1",
			wantSubresource: "attach",
			wantLongRunning: true,
		},
		"port forward to a pod": {
			method:          http.MethodPost,
			url:             "/api/v1/namespaces/ns-1/pods/pod-1/portforward",
			wantVerb:        "create",
			wantResource:    "pods",
			wantName:        "pod-1",
			wantSubresource: "portforward",
			wantLongRunning: true,
		},
		"follow pod logs": {
			method:          http.MethodGet,
			url:             "/api/v1/namespaces/ns-1/pods/pod-1/log?follow=true",
			wantVerb:        "get",
			wantResource:    "pods",
			wantName:        "pod-1",
			wantSubresource: "log",
			wantLongRunning: true,
		},
		"proxy to a service": {
			method:          http.MethodGet,
			url:             "/api/v1/namespaces/ns-1/services/svc-1/proxy",
			wantVerb:        "get",
			wantResource:    "services",
			wantName:        "svc-1",
			wantSubresource: "proxy",
			wantLongRunning: true,
		},
		// A service proxy usually names a port and a path to reach inside the
		// service. The port travels in the object name and the path is a
		// trailing part the resolver does not interpret, so neither disturbs
		// the subresource the long-running check matches on.
		"proxy to a service port and path": {
			method:          http.MethodGet,
			url:             "/api/v1/namespaces/ns-1/services/svc-1:8080/proxy/healthz",
			wantVerb:        "get",
			wantResource:    "services",
			wantName:        "svc-1:8080",
			wantSubresource: "proxy",
			wantLongRunning: true,
		},
		"proxy to a node": {
			method:          http.MethodGet,
			url:             "/api/v1/nodes/node-1/proxy/logs",
			wantVerb:        "get",
			wantResource:    "nodes",
			wantName:        "node-1",
			wantSubresource: "proxy",
			wantLongRunning: true,
		},
		// The proxy verb, as opposed to the proxy subresource above, only ever
		// arrives through the deprecated verb-via-path form the resolver still
		// parses (specialVerbs). It allows no subresource, so it is the verb
		// alone that has to make the request long running — which is why the
		// verb set carries proxy as well as watch.
		"proxy verb through the legacy path": {
			method:          http.MethodGet,
			url:             "/api/v1/proxy/namespaces/ns-1/services/svc-1",
			wantVerb:        "proxy",
			wantResource:    "services",
			wantName:        "svc-1",
			wantLongRunning: true,
		},
		"watch pods in the core group": {
			method:          http.MethodGet,
			url:             "/api/v1/namespaces/ns-1/pods?watch=true",
			wantVerb:        "watch",
			wantResource:    "pods",
			wantLongRunning: true,
		},
		"watch deployments in a named group": {
			method:          http.MethodGet,
			url:             "/apis/apps/v1/namespaces/ns-1/deployments?watch=true",
			wantVerb:        "watch",
			wantResource:    "deployments",
			wantLongRunning: true,
		},
		"list pods": {
			method:       http.MethodGet,
			url:          "/api/v1/namespaces/ns-1/pods",
			wantVerb:     "list",
			wantResource: "pods",
		},
		"get a pod": {
			method:       http.MethodGet,
			url:          "/api/v1/namespaces/ns-1/pods/pod-1",
			wantVerb:     "get",
			wantResource: "pods",
			wantName:     "pod-1",
		},
		"create a pod": {
			method:       http.MethodPost,
			url:          "/api/v1/namespaces/ns-1/pods",
			wantVerb:     "create",
			wantResource: "pods",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.url, nil)

			info, err := resolver.NewRequestInfo(req)
			if err != nil {
				t.Fatalf("failed to resolve request info for %s: %s", test.url, err)
			}

			if !info.IsResourceRequest {
				t.Errorf("%s resolved as a non-resource request, want a resource request", test.url)
			}

			if info.Verb != test.wantVerb {
				t.Errorf("verb for %s = %q, want %q", test.url, info.Verb, test.wantVerb)
			}

			if info.Resource != test.wantResource {
				t.Errorf("resource for %s = %q, want %q", test.url, info.Resource, test.wantResource)
			}

			if info.Name != test.wantName {
				t.Errorf("name for %s = %q, want %q", test.url, info.Name, test.wantName)
			}

			if info.Subresource != test.wantSubresource {
				t.Errorf("subresource for %s = %q, want %q", test.url, info.Subresource, test.wantSubresource)
			}

			if got := longRunningRequests(req, info); got != test.wantLongRunning {
				t.Errorf("longRunningRequests(%s) = %t, want %t", test.url, got, test.wantLongRunning)
			}
		})
	}
}

// fakeBackend is an audit.Backend that records whether it was shut down and
// can be told to fail Run.
type fakeBackend struct {
	runErr   error
	shutdown bool
}

func (f *fakeBackend) ProcessEvents(_ ...*auditinternal.Event) bool { return true }
func (f *fakeBackend) Run(_ <-chan struct{}) error                  { return f.runErr }
func (f *fakeBackend) Shutdown()                                    { f.shutdown = true }
func (f *fakeBackend) String() string                               { return "fake" }

// newTestAuditWithBackend builds an Audit reporting through root whose backend
// is the supplied fake, so Shutdown can be exercised without a real audit sink.
func newTestAuditWithBackend(t testing.TB, root *slog.Logger, backend audit.Backend) *Audit {
	t.Helper()

	a, err := New(Config{Options: apiserveroptions.NewAuditOptions(), ExternalAddress: "127.0.0.1:6443", SecureServing: nil},
		logging.ForComponent(root, logging.ComponentAudit))
	if err != nil {
		t.Fatalf("failed to create auditor: %s", err)
	}
	a.serverConfig.AuditBackend = backend
	return a
}

// TestShutdownFlushesAndRecordsCompletion pins what Shutdown can actually
// observe: it flushes the backend and records the flush as completed. The
// upstream backend interface gives it no failure to report.
func TestShutdownFlushesAndRecordsCompletion(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)
	backend := &fakeBackend{}
	a := newTestAuditWithBackend(t, root, backend)

	a.Shutdown()

	if !backend.shutdown {
		t.Fatal("Shutdown did not flush the backend")
	}
	cap.Only(t, logging.EventAuditFlushCompleted)
}

// TestRunReportsBackendStarted covers the success case: a backend that starts
// announces itself, naming which backend is running so the record can be
// correlated with the audit flags.
func TestRunReportsBackendStarted(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)
	a := newTestAuditWithBackend(t, root, &fakeBackend{})

	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	rec := cap.Only(t, logging.EventAuditBackendStarted)
	if rec.String("backend_kind") != "fake" {
		t.Fatalf("backend_kind = %q, want fake", rec.String("backend_kind"))
	}
	if rec.String("level") != "INFO" {
		t.Fatalf("level = %q, want INFO", rec.String("level"))
	}
}

// TestRunReturnsBackendFailure covers the failure case: a backend that cannot
// start is an error the process cannot serve correctly through, so the cause
// reaches the caller, which reports it once as the startup failure. Nothing is
// logged here, and in particular no start.
func TestRunReturnsBackendFailure(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)
	a := newTestAuditWithBackend(t, root, &fakeBackend{runErr: errors.New("webhook unreachable")})

	err := a.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "webhook unreachable") {
		t.Fatalf("Start() = %v, want the backend's start error", err)
	}
	if len(cap.Records()) != 0 {
		t.Fatalf("a failed start was logged by the auditor as well as returned: %s", cap.Raw())
	}
}

// TestRunWithoutBackendIsSilent pins the no-audit-configured case: with no
// backend there is no lifecycle to report, and an empty record stream is how a
// consumer tells "auditing off" from "auditing broken".
func TestRunWithoutBackendIsSilent(t *testing.T) {
	root, cap := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, cap)
	a := newTestAuditWithBackend(t, root, nil)

	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.Shutdown()
	if raw := cap.Raw(); raw != "" {
		t.Fatalf("records emitted with no audit backend configured: %s", raw)
	}
}

// TestWithRequestInfoResolvesCoreGroupAsResourceRequest pins
// LegacyAPIGroupPrefixes. Without it every /api request parses as a
// non-resource request whose verb is the lowercased HTTP method, which would
// silently collapse the k8s_verb metric label to "other" and the scope label
// to "none" for the whole core group.
func TestWithRequestInfoResolvesCoreGroupAsResourceRequest(t *testing.T) {
	a, err := New(Config{ExternalAddress: "0.0.0.0:1234", SecureServing: new(server.SecureServingInfo)}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		method, path      string
		wantVerb, wantRes string
		wantNamespace     string
		wantResource      bool
	}{
		"core group list in a namespace": {
			method: http.MethodGet, path: "/api/v1/namespaces/team-a/pods",
			wantVerb: "list", wantRes: "pods", wantNamespace: "team-a", wantResource: true,
		},
		"core group watch": {
			method: http.MethodGet, path: "/api/v1/pods?watch=true",
			wantVerb: "watch", wantRes: "pods", wantResource: true,
		},
		"named group create": {
			method: http.MethodPost, path: "/apis/apps/v1/namespaces/team-a/deployments",
			wantVerb: "create", wantRes: "deployments", wantNamespace: "team-a", wantResource: true,
		},
		"non-resource path keeps the raw method": {
			method: http.MethodPost, path: "/healthz",
			wantVerb: "post", wantResource: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var got *request.RequestInfo
			h := a.WithRequestInfo(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got, _ = request.RequestInfoFrom(r.Context())
			}))
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.path, nil))
			if got == nil {
				t.Fatal("no RequestInfo on the context")
			}
			if got.IsResourceRequest != tc.wantResource || got.Verb != tc.wantVerb ||
				got.Resource != tc.wantRes || got.Namespace != tc.wantNamespace {
				t.Fatalf("got %+v, want resource=%v verb=%q resource=%q namespace=%q",
					got, tc.wantResource, tc.wantVerb, tc.wantRes, tc.wantNamespace)
			}
		})
	}
}

// TestNewRequiresLogger pins that the logger is a required collaborator: a nil
// one fails at construction rather than on the first record.
func TestNewRequiresLogger(t *testing.T) {
	if _, err := New(Config{ExternalAddress: "0.0.0.0:1234", SecureServing: new(server.SecureServingInfo)}, nil); err == nil {
		t.Fatal("New(nil logger) error = nil, want an error")
	}
}

// forbiddenAuditEvent is the subset of an audit.k8s.io/v1 Event this test
// asserts on. Decoding into a local struct keeps the assertions independent of
// the apiserver's internal/external event conversions.
type forbiddenAuditEvent struct {
	Stage string `json:"stage"`
	User  struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"user"`
	ResponseStatus *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"responseStatus"`
}

// forbiddenAuditPolicy is a Metadata-level policy for every request.
// RequestReceived is omitted so the backend emits exactly one event per
// request, keeping the assertions unambiguous.
const forbiddenAuditPolicy = `apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - RequestReceived
rules:
  - level: Metadata
`

// newForbiddenTestAudit builds a real Audit backed by a file log backend and a
// Metadata policy, returning it alongside the path the events are written to.
func newForbiddenTestAudit(t *testing.T) (*Audit, string) {
	t.Helper()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(forbiddenAuditPolicy), 0600); err != nil {
		t.Fatalf("writing audit policy: %s", err)
	}
	logPath := filepath.Join(dir, "audit.log")

	opts := apiserveroptions.NewAuditOptions()
	opts.PolicyFile = policyPath
	opts.LogOptions.Path = logPath

	a, err := New(Config{Options: opts, ExternalAddress: "0.0.0.0:1234", SecureServing: new(server.SecureServingInfo)}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("creating auditor: %s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := a.Start(ctx); err != nil {
		t.Fatalf("running audit backend: %s", err)
	}

	return a, logPath
}

// readForbiddenAuditEvents flushes the backend and returns every event written
// to path.
func readForbiddenAuditEvents(t *testing.T, a *Audit, path string) []forbiddenAuditEvent {
	t.Helper()

	a.Shutdown()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log %q: %s", path, err)
	}

	var events []forbiddenAuditEvent
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var event forbiddenAuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decoding audit event %q: %s", line, err)
		}
		events = append(events, event)
	}

	return events
}

// TestWithRequestAuditsAuthenticatedIdentity is the regression guard against
// auditing a refusal of an authenticated request through the
// failed-authentication chain. The request authenticated
// successfully and was then refused by the proxy, so the audit record must name
// the identity that was presented and must not read as an authentication
// failure.
//
// The assertions are deliberately confined to what this handler decides: the
// stage, the identity, the status code, and the absence of an
// authentication-failure message. The event's verb and objectRef are not
// asserted because they are decided by the RequestInfo resolver, so they move
// with its configuration — a core-group path like the one below is classified
// as a non-resource request (verb "get", no objectRef) unless the resolver is
// given the legacy API group prefixes, which turns it into a resource request
// (verb "list", objectRef present). Assert on those only against the resolver
// this package actually builds.
func TestWithRequestAuditsAuthenticatedIdentity(t *testing.T) {
	a, logPath := newForbiddenTestAudit(t)

	handler := a.WithRequestInfo(a.WithRequest(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Error(rw, "forbidden", http.StatusForbidden)
	})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
	// A bearer token is present so that, were the refusal audited through
	// WithFailedAuthentication, the event would carry its
	// "Authentication failed, attempted: bearer" message.
	req.Header.Set("Authorization", "bearer fake-token")
	req = req.WithContext(request.WithUser(req.Context(), &authuser.DefaultInfo{
		Name:   "alice",
		Groups: []string{"system:masters"},
	}))

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if got, want := rw.Result().StatusCode, http.StatusForbidden; got != want {
		t.Errorf("unexpected response code, exp=%d got=%d", want, got)
	}

	events := readForbiddenAuditEvents(t, a, logPath)
	if len(events) != 1 {
		t.Fatalf("expected exactly one audit event, got %d: %+v", len(events), events)
	}
	event := events[0]

	if event.Stage != "ResponseComplete" {
		t.Errorf("expected a ResponseComplete audit event, got stage %q", event.Stage)
	}

	// The regression guard: the authenticated identity, not an empty user.
	if event.User.Username != "alice" {
		t.Errorf("audit event does not carry the authenticated user, exp=alice got=%q", event.User.Username)
	}
	if len(event.User.Groups) != 1 || event.User.Groups[0] != "system:masters" {
		t.Errorf("audit event does not carry the authenticated groups, exp=[system:masters] got=%v", event.User.Groups)
	}

	if event.ResponseStatus == nil {
		t.Fatal("audit event has no responseStatus")
	}
	if got, want := event.ResponseStatus.Code, http.StatusForbidden; got != want {
		t.Errorf("unexpected audited response code, exp=%d got=%d", want, got)
	}

	// Not an authentication-failure record.
	if strings.Contains(event.ResponseStatus.Message, "Authentication failed") {
		t.Errorf("audit event reads as an authentication failure: %q", event.ResponseStatus.Message)
	}
}

// TestWithFailedAuthenticationAuditsFailedAuthentication is the regression
// guard for the missing WithAuditInit in the failed-authentication chain
// (TremoloSecurity/kube-oidc-proxy#92). Without an initialised audit context
// the failed-authentication filter finds auditing disabled and a rejected
// request leaves no trace in the audit log at all — the exact case an audit
// log exists for.
//
// Assertions are confined to what this chain decides: that exactly one event
// is written, at ResponseStarted (the stage the failed-auth filter's decorated
// response writer records on WriteHeader), carrying the 401 and the
// authentication-failure message, with no authenticated identity. Verb and
// objectRef are the RequestInfo resolver's decision and are covered elsewhere.
func TestWithFailedAuthenticationAuditsFailedAuthentication(t *testing.T) {
	a, logPath := newForbiddenTestAudit(t)

	handler := a.WithRequestInfo(a.WithFailedAuthentication(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusUnauthorized)
	})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/kube-system/pods", nil)
	req.Header.Set("Authorization", "bearer some-invalid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	events := readForbiddenAuditEvents(t, a, logPath)
	if len(events) != 1 {
		t.Fatalf("expected exactly one audit event for a failed authentication, got %d: %+v", len(events), events)
	}

	event := events[0]
	if event.Stage != "ResponseStarted" {
		t.Errorf("expected stage ResponseStarted, got %q", event.Stage)
	}
	if event.User.Username != "" {
		t.Errorf("failed authentication must not record an identity, got %q", event.User.Username)
	}
	if event.ResponseStatus == nil {
		t.Fatalf("expected a responseStatus on the event, got none")
	}
	if event.ResponseStatus.Code != http.StatusUnauthorized {
		t.Errorf("expected responseStatus code 401, got %d", event.ResponseStatus.Code)
	}
	if !strings.Contains(event.ResponseStatus.Message, "Authentication failed, attempted: bearer") {
		t.Errorf("expected the authentication-failure message naming the attempted method, got %q", event.ResponseStatus.Message)
	}
}
