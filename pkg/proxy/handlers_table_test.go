// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

// handlersCase is one end-to-end case through the proxy's handler chain: the
// inbound request, the authenticator's answer, and the response, outbound
// identity and access record expected.
type handlersCase struct {
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
	expReason     metrics.Reason
	expAuthMethod metrics.AuthMethod
}

type authResponse struct {
	resp *authenticator.Response
	pass bool
	err  error
}

// runHandlersCases drives each case through a proxy wired with a fake
// authenticator and transport, and checks the response, the forwarded
// identity and the access record.
func runHandlersCases(t *testing.T, tests map[string]handlersCase) {
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var opts []func(*Dependencies)
			if test.config != nil {
				opts = append(opts, withConfig(*test.config))
			}
			p := newTestProxy(t, opts...)

			w := httptest.NewRecorder()

			if test.authResponse != nil {
				p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), test.expAuthToken).DoAndReturn(
					oidcAnswer(test.authResponse.resp, test.authResponse.pass, test.authResponse.err))
			}

			p.fakeRT.expUser = test.expUser
			p.fakeRT.expGroup = test.expGroup
			p.fakeRT.expExtra = test.expExtra
			p.fakeRT.expUID = test.expUID

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
			if got := rec.String("reason"); got != string(test.expReason) {
				t.Errorf("reason = %q, want %q", got, test.expReason)
			}
			if got := rec.String("auth_method"); got != string(test.expAuthMethod) {
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

// TestHandlersAuthentication covers the chain for requests that impersonate
// nobody: refused credentials, missing claims and plain forwarding.
func TestHandlersAuthentication(t *testing.T) {
	runHandlersCases(t, map[string]handlersCase{
		"an empty request should 401": {
			expEvent:      "AuFail",
			expReason:     metrics.ReasonUnauthorized,
			expAuthMethod: metrics.AuthMethodNone,
			req:           new(http.Request),
			expCode:       http.StatusUnauthorized,
			expBody:       "Unauthorized",
		},
		"a request with a badly formed token should 401": {
			expEvent:      "AuFail",
			expReason:     metrics.ReasonUnauthorized,
			expAuthMethod: metrics.AuthMethodNone,
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
			expReason:     metrics.ReasonUnauthorized,
			expAuthMethod: metrics.AuthMethodNone,
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
			expReason:     metrics.ReasonUnauthorized,
			expAuthMethod: metrics.AuthMethodNone,
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
			expReason:     metrics.ReasonUnauthorized,
			expAuthMethod: metrics.AuthMethodNone,
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
		"an authed request with no username is token should 403": {
			expEvent:      "AuFail",
			expReason:     metrics.ReasonNoUsernameClaim,
			expAuthMethod: metrics.AuthMethodOIDC,
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
			expAuthMethod: metrics.AuthMethodOIDC,
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
	})
}
