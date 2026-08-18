// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/apiserver/pkg/endpoints/request"
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
