// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
			p := newTestProxy(t, withConfig(*test.config))
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
				_, err := p.roundTrip(req)
				if err != nil {
					t.Errorf("unexpected error: %s", err)
					t.FailNow()
				}
			})

			handler = p.withFilterChain(handler)
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

func TestParseTrustedProxies(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in      []string
		wantLen int
		wantErr bool
	}{
		"nil is no trust": {
			in:      nil,
			wantLen: 0,
		},
		"empty slice is no trust": {
			in:      []string{},
			wantLen: 0,
		},
		"valid IPv4 CIDRs": {
			in:      []string{"10.0.0.0/8", "192.168.0.0/16"},
			wantLen: 2,
		},
		"valid IPv6 CIDR": {
			in:      []string{"fd00::/8"},
			wantLen: 1,
		},
		"whitespace is trimmed": {
			in:      []string{" 10.0.0.0/8 "},
			wantLen: 1,
		},
		"bare IP without mask is rejected": {
			in:      []string{"10.0.0.1"},
			wantErr: true,
		},
		"garbage is rejected": {
			in:      []string{"not-a-cidr"},
			wantErr: true,
		},
		"empty entry is rejected": {
			in:      []string{"10.0.0.0/8", ""},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := parseTrustedProxies(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseTrustedProxies(%v) = nil error, want error", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTrustedProxies(%v) unexpected error: %v", tc.in, err)
			}
			if len(got) != tc.wantLen {
				t.Errorf("parseTrustedProxies(%v) len = %d, want %d", tc.in, len(got), tc.wantLen)
			}
		})
	}
}

// FuzzParseTrustedProxies drives trusted-proxy CIDR parsing with arbitrary
// input. Getting this wrong decides whether X-Forwarded-For is believed, so a
// malformed entry must fail loudly rather than yield a partial or unexpectedly
// wide set of networks.
func FuzzParseTrustedProxies(f *testing.F) {
	for _, seed := range []string{
		"",
		"10.0.0.0/8",
		" 192.168.0.1/32 ",
		"2001:db8::/32",
		"not-a-cidr",
		"10.0.0.0/8,not-a-cidr",
		"10.0.0.0/8, ,192.168.0.0/16",
		"10.0.0.1/0",
		"::/0",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, joined string) {
		cidrs := strings.Split(joined, ",")

		nets, err := parseTrustedProxies(cidrs)
		if err != nil {
			if nets != nil {
				t.Fatalf("networks returned alongside error %q: %v", err, nets)
			}
			return
		}

		if len(nets) != len(cidrs) {
			t.Fatalf("parsed %d networks from %d entries (%q)", len(nets), len(cidrs), joined)
		}

		for i, n := range nets {
			if n == nil {
				t.Fatalf("entry %d (%q) parsed to a nil network", i, cidrs[i])
			}
			// A parsed network is always the masked base address, so it must
			// contain itself and survive a canonical-form round trip.
			if !n.Contains(n.IP) {
				t.Fatalf("network %s does not contain its own base address", n)
			}
			_, again, err := net.ParseCIDR(n.String())
			if err != nil {
				t.Fatalf("re-parsing %s from entry %q: %s", n, cidrs[i], err)
			}
			if again.String() != n.String() {
				t.Fatalf("round trip changed %s into %s", n, again)
			}
		}
	})
}
