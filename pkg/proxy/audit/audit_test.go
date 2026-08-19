// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/apiserver/pkg/endpoints/request"
	apiserveroptions "k8s.io/apiserver/pkg/server/options"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
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
	auditor, err := New(&options.AuditOptions{AuditOptions: apiserveroptions.NewAuditOptions()}, "127.0.0.1:6443", nil)
	if err != nil {
		t.Fatalf("failed to create auditor: %s", err)
	}

	resolver := auditor.serverConfig.RequestInfoResolver

	tests := map[string]struct {
		method          string
		url             string
		wantVerb        string
		wantResource    string
		wantSubresource string
		wantLongRunning bool
	}{
		"exec into a pod": {
			method:          http.MethodPost,
			url:             "/api/v1/namespaces/ns-1/pods/pod-1/exec?command=sh&container=c-1&stdout=true",
			wantVerb:        "create",
			wantResource:    "pods",
			wantSubresource: "exec",
			wantLongRunning: true,
		},
		"attach to a pod": {
			method:          http.MethodPost,
			url:             "/api/v1/namespaces/ns-1/pods/pod-1/attach?container=c-1",
			wantVerb:        "create",
			wantResource:    "pods",
			wantSubresource: "attach",
			wantLongRunning: true,
		},
		"port forward to a pod": {
			method:          http.MethodPost,
			url:             "/api/v1/namespaces/ns-1/pods/pod-1/portforward",
			wantVerb:        "create",
			wantResource:    "pods",
			wantSubresource: "portforward",
			wantLongRunning: true,
		},
		"follow pod logs": {
			method:          http.MethodGet,
			url:             "/api/v1/namespaces/ns-1/pods/pod-1/log?follow=true",
			wantVerb:        "get",
			wantResource:    "pods",
			wantSubresource: "log",
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

			if info.Subresource != test.wantSubresource {
				t.Errorf("subresource for %s = %q, want %q", test.url, info.Subresource, test.wantSubresource)
			}

			if got := longRunningRequests(req, info); got != test.wantLongRunning {
				t.Errorf("longRunningRequests(%s) = %t, want %t", test.url, got, test.wantLongRunning)
			}
		})
	}
}
