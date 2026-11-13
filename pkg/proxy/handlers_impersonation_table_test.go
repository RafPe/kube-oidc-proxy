// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"net/http"
	"testing"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

// TestHandlersImpersonation covers the chain for requests that carry
// Impersonate-* headers: every authorized target kind, every refused one, and
// the malformed shapes.
func TestHandlersImpersonation(t *testing.T) {
	runHandlersCases(t, map[string]handlersCase{
		"a request with unauth with impersonation should 401": {
			expEvent:      "AuFail",
			expReason:     metrics.ReasonUnauthorized,
			expAuthMethod: metrics.AuthMethodNone,
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
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expReason:     metrics.ReasonImpersonationDenied,
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expReason:     metrics.ReasonImpersonationDenied,
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expReason:     metrics.ReasonImpersonationDenied,
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expReason:     metrics.ReasonImpersonationDenied,
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expReason:     metrics.ReasonMalformedImpersonation,
			expAuthMethod: metrics.AuthMethodOIDC,
			req: &http.Request{
				Header: http.Header{
					"Authorization":     []string{"bearer fake-token"},
					"Impersonate-Group": []string{"bar"},
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
			expCode: http.StatusBadRequest,
			expBody: "no Impersonate-User header found for request",
		},
		"an authed request with impersonation extra missing user should fail": {
			expEvent:      "AuFail",
			expReason:     metrics.ReasonMalformedImpersonation,
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expCode: http.StatusBadRequest,
			expBody: "no Impersonate-User header found for request",
		},
		"an authed request with impersonation uid missing user should fail": {
			expEvent:      "AuFail",
			expReason:     metrics.ReasonMalformedImpersonation,
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expCode: http.StatusBadRequest,
			expBody: "no Impersonate-User header found for request",
		},
		"an authed request with an invalid impersonation header should fail": {
			expEvent:      "AuFail",
			expReason:     metrics.ReasonMalformedImpersonation,
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expCode: http.StatusBadRequest,
			expBody: `unknown impersonation header: "Impersonate-Not-Real"`,
		},

		// END IMPERSONATION TESTS
		"an authed request with user, group, extra but disabled impersonation should return no impersonation and should 200": {
			expEvent:      "AuSuccess",
			expAuthMethod: metrics.AuthMethodOIDC,
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
	})
}
