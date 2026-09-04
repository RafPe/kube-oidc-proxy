// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/endpoints/request"
	apiserveroptions "k8s.io/apiserver/pkg/server/options"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
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
	auditor, err := New(&options.AuditOptions{AuditOptions: apiserveroptions.NewAuditOptions()}, "127.0.0.1:6443", nil, slog.New(slog.DiscardHandler))
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

// fakeBackend is an audit.Backend that records whether it was shut down. It
// implements errorReporter so a test can drive both Shutdown outcomes: the
// upstream audit.Backend interface has a Shutdown that returns nothing, so a
// backend that knows its flush failed can only say so through this extension.
type fakeBackend struct {
	shutdownErr error
	shutdown    bool
}

func (f *fakeBackend) ProcessEvents(_ ...*auditinternal.Event) bool { return true }
func (f *fakeBackend) Run(_ <-chan struct{}) error                  { return nil }
func (f *fakeBackend) Shutdown()                                    { f.shutdown = true }
func (f *fakeBackend) String() string                               { return "fake" }
func (f *fakeBackend) ShutdownErr() error                           { return f.shutdownErr }

// newTestAuditWithBackend builds an Audit reporting through root whose backend
// is the supplied fake, so Shutdown can be exercised without a real audit sink.
func newTestAuditWithBackend(t testing.TB, root *slog.Logger, backend audit.Backend) *Audit {
	t.Helper()

	a, err := New(&options.AuditOptions{AuditOptions: apiserveroptions.NewAuditOptions()}, "127.0.0.1:6443", nil,
		logging.ForComponent(root, logging.ComponentAudit))
	if err != nil {
		t.Fatalf("failed to create auditor: %s", err)
	}
	a.serverConfig.AuditBackend = backend
	return a
}

// TestShutdownReportsFlushResult covers the success case: the backend's
// Shutdown returns without reporting an error, so the flush is recorded as
// completed and Shutdown reports no failure to the caller.
func TestShutdownReportsFlushResult(t *testing.T) {
	root, cap := logtest.New(t, 0)
	a := newTestAuditWithBackend(t, root, &fakeBackend{shutdownErr: nil})
	if err := a.Shutdown(); err != nil {
		t.Fatal(err)
	}
	cap.Only(t, logging.EventAuditFlushCompleted)
}

// TestShutdownReportsFlushFailure covers the failure case: a backend that
// reports a shutdown error through errorReporter yields audit.flush.failed and
// the error reaches the caller, so a lost audit flush is not silent.
func TestShutdownReportsFlushFailure(t *testing.T) {
	root, cap := logtest.New(t, 0)
	a := newTestAuditWithBackend(t, root, &fakeBackend{shutdownErr: errors.New("flush timed out")})
	err := a.Shutdown()
	if err == nil {
		t.Fatal("Shutdown reported success for a backend that failed to flush")
	}
	if got := cap.Only(t, logging.EventAuditFlushFailed).String("error_message"); got != "flush timed out" {
		t.Fatalf("error_message = %q, want %q", got, "flush timed out")
	}
	if len(cap.ByEvent(logging.EventAuditFlushCompleted)) != 0 {
		t.Fatal("a failed flush also reported completion")
	}
}
