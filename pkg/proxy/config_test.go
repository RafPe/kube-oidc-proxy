// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

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

			p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(oidcAnswer(authResponse, true, nil))

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
