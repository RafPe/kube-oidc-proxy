// Copyright Jetstack Ltd. See LICENSE for details.
package clientip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	utilnet "k8s.io/apimachinery/pkg/util/net"
)

// mustCIDRs parses CIDR strings into networks, failing the test on error.
func mustCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("mustCIDRs: parse %q: %v", c, err)
		}
		nets = append(nets, n)
	}
	return nets
}

func TestResolve(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		remoteAddr string
		xff        string
		trusted    []*net.IPNet
		want       string
	}{
		// Security core: the default (no trusted proxies) never honours XFF, so a
		// client cannot spoof its resolved IP.
		"default trusts nothing, ignores XFF": {
			remoteAddr: "203.0.113.7:5555",
			xff:        "1.2.3.4",
			trusted:    nil,
			want:       "203.0.113.7",
		},
		"untrusted peer cannot spoof via XFF": {
			remoteAddr: "203.0.113.7:5555",
			xff:        "1.2.3.4",
			trusted:    mustCIDRs(t, "10.0.0.0/8"),
			want:       "203.0.113.7",
		},
		"untrusted peer, multi-hop XFF ignored": {
			remoteAddr: "203.0.113.7:5555",
			xff:        "1.2.3.4, 5.6.7.8, 9.10.11.12",
			trusted:    mustCIDRs(t, "10.0.0.0/8"),
			want:       "203.0.113.7",
		},

		// Trusted peer: XFF is honoured.
		"trusted peer, single hop honoured": {
			remoteAddr: "10.0.0.1:5555",
			xff:        "203.0.113.7",
			trusted:    mustCIDRs(t, "10.0.0.0/8"),
			want:       "203.0.113.7",
		},
		"trusted peer, multi-hop returns first untrusted from right": {
			remoteAddr: "10.0.0.1:5555",
			xff:        "203.0.113.7, 10.0.0.9, 10.0.0.8",
			trusted:    mustCIDRs(t, "10.0.0.0/8"),
			want:       "203.0.113.7",
		},
		"trusted peer, untrusted hop nearest proxy wins": {
			remoteAddr: "10.0.0.1:5555",
			xff:        "9.9.9.9, 8.8.8.8, 203.0.113.7",
			trusted:    mustCIDRs(t, "10.0.0.0/8"),
			want:       "203.0.113.7",
		},
		"trusted peer, whole chain trusted falls back to peer": {
			remoteAddr: "10.0.0.1:5555",
			xff:        "10.0.0.2, 10.0.0.3",
			trusted:    mustCIDRs(t, "10.0.0.0/8"),
			want:       "10.0.0.1",
		},
		"trusted peer, empty XFF returns peer": {
			remoteAddr: "10.0.0.1:5555",
			xff:        "",
			trusted:    mustCIDRs(t, "10.0.0.0/8"),
			want:       "10.0.0.1",
		},

		// Malformed values: a malformed hop stops the walk and falls back to peer,
		// so garbage cannot be promoted to a client IP.
		"trusted peer, malformed hop falls back to peer": {
			remoteAddr: "10.0.0.1:5555",
			xff:        "not-an-ip",
			trusted:    mustCIDRs(t, "10.0.0.0/8"),
			want:       "10.0.0.1",
		},
		"trusted peer, malformed hop between trusted stops walk": {
			remoteAddr: "10.0.0.1:5555",
			xff:        "203.0.113.7, garbage, 10.0.0.9",
			trusted:    mustCIDRs(t, "10.0.0.0/8"),
			want:       "10.0.0.1",
		},

		// IPv6.
		"IPv6 trusted peer honours IPv6 XFF": {
			remoteAddr: "[fd00::1]:5555",
			xff:        "2001:db8::42",
			trusted:    mustCIDRs(t, "fd00::/8"),
			want:       "2001:db8::42",
		},
		"IPv6 untrusted peer ignores XFF": {
			remoteAddr: "[2001:db8::99]:5555",
			xff:        "2001:db8::42",
			trusted:    mustCIDRs(t, "fd00::/8"),
			want:       "2001:db8::99",
		},
		"IPv6 trusted peer, mixed chain returns first untrusted from right": {
			remoteAddr: "[fd00::1]:5555",
			xff:        "203.0.113.7, fd00::2",
			trusted:    mustCIDRs(t, "fd00::/8"),
			want:       "203.0.113.7",
		},

		// Peer address edge cases.
		"peer without port falls through to raw value": {
			remoteAddr: "203.0.113.7",
			xff:        "1.2.3.4",
			trusted:    mustCIDRs(t, "10.0.0.0/8"),
			want:       "203.0.113.7",
		},
		"empty remote addr yields empty": {
			remoteAddr: "",
			xff:        "",
			trusted:    nil,
			want:       "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := Resolve(tc.remoteAddr, tc.xff, tc.trusted)
			if got != tc.want {
				t.Errorf("Resolve(%q, %q) = %q, want %q",
					tc.remoteAddr, tc.xff, got, tc.want)
			}
		})
	}
}

func TestPeerHost(t *testing.T) {
	tests := map[string]struct{ in, exp string }{
		"ipv4 host port":    {"1.2.3.4:8080", "1.2.3.4"},
		"ipv6 host port":    {"[::1]:8080", "::1"},
		"bare ipv4 no port": {"1.2.3.4", "1.2.3.4"},
		"empty":             {"", ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := PeerHost(tc.in); got != tc.exp {
				t.Errorf("PeerHost(%q) = %q, want %q", tc.in, got, tc.exp)
			}
		})
	}
}

// TestSanitize pins the trusted-proxy contract as applied to the inbound
// forwarding headers. The final assertion runs the apiserver's own
// utilnet.SourceIPs over a request carrying the sanitized headers -- that
// function is what the audit filter uses to fill sourceIPs, so it is the
// audit-visible outcome that is pinned, not just the header rewrite.
func TestSanitize(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		trusted      []*net.IPNet
		xff          string
		realIP       string
		expIP        string
		expXFF       string
		expSourceIPs []string
	}{
		"no trusted proxies: forwarded headers are stripped": {
			xff:          "1.2.3.4",
			realIP:       "9.9.9.9",
			expIP:        "10.0.0.5",
			expSourceIPs: []string{"10.0.0.5"},
		},
		"trusted peer: chain collapses to the resolved client": {
			trusted:      mustCIDRs(t, "10.0.0.0/8"),
			xff:          "1.2.3.4, 10.0.0.9",
			expIP:        "1.2.3.4",
			expXFF:       "1.2.3.4",
			expSourceIPs: []string{"1.2.3.4", "10.0.0.5"},
		},
		"entirely trusted chain: stripped": {
			trusted:      mustCIDRs(t, "10.0.0.0/8"),
			xff:          "10.0.0.7, 10.0.0.9",
			expIP:        "10.0.0.5",
			expSourceIPs: []string{"10.0.0.5"},
		},
		"malformed hop: stripped": {
			trusted:      mustCIDRs(t, "10.0.0.0/8"),
			xff:          "not-an-ip, 10.0.0.9",
			expIP:        "10.0.0.5",
			expSourceIPs: []string{"10.0.0.5"},
		},
		"x-real-ip alone is removed": {
			trusted:      mustCIDRs(t, "10.0.0.0/8"),
			realIP:       "9.9.9.9",
			expIP:        "10.0.0.5",
			expSourceIPs: []string{"10.0.0.5"},
		},
		"no forwarding headers: untouched": {
			trusted:      mustCIDRs(t, "10.0.0.0/8"),
			expIP:        "10.0.0.5",
			expSourceIPs: []string{"10.0.0.5"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
			req.RemoteAddr = "10.0.0.5:12345"
			if test.xff != "" {
				req.Header.Set(HeaderForwardedFor, test.xff)
			}
			if test.realIP != "" {
				req.Header.Set(HeaderRealIP, test.realIP)
			}
			inbound := req.Header.Clone()

			ip, out := Sanitize(req.RemoteAddr, req.Header, test.trusted)

			if ip != test.expIP {
				t.Errorf("ip = %q, want %q", ip, test.expIP)
			}
			if got := out.Get(HeaderForwardedFor); got != test.expXFF {
				t.Errorf("X-Forwarded-For after sanitizing = %q, want %q", got, test.expXFF)
			}
			if got := out.Get(HeaderRealIP); got != "" {
				t.Errorf("X-Real-Ip must always be removed, got %q", got)
			}
			if !reflect.DeepEqual(req.Header, inbound) {
				t.Errorf("Sanitize modified the inbound headers: %v, want %v", req.Header, inbound)
			}

			req.Header = out
			var sourceIPs []string
			for _, ip := range utilnet.SourceIPs(req) {
				sourceIPs = append(sourceIPs, ip.String())
			}
			if !reflect.DeepEqual(sourceIPs, test.expSourceIPs) {
				t.Errorf("audit-visible source IPs = %v, want %v", sourceIPs, test.expSourceIPs)
			}
		})
	}
}
