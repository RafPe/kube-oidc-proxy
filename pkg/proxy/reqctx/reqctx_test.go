// Copyright Jetstack Ltd. See LICENSE for details.
package reqctx

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

func TestResolveClientIP(t *testing.T) {
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
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := ResolveClientIP(tc.remoteAddr, tc.xff, tc.trusted)
			if got != tc.want {
				t.Errorf("ResolveClientIP(%q, %q) = %q, want %q",
					tc.remoteAddr, tc.xff, got, tc.want)
			}
		})
	}
}

// TestClientIP_DefaultTrustsNothing verifies the request-level entry point
// uses the direct peer by default and does not honour a forged XFF header.
func TestClientIP_DefaultTrustsNothing(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "203.0.113.7:5555",
		Header:     http.Header{"X-Forwarded-For": []string{"1.2.3.4"}},
	}

	if got := ClientIP(WithResolvedClient(req, nil)); got != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want %q", got, "203.0.113.7")
	}
}

// TestClientIP_TrustedPeerHonoursXFF verifies XFF is honoured when the peer is
// a configured trusted proxy. The returned value is exactly what handlers.go
// writes into extra[UserHeaderClientIPKey] (the Remote-Client-IP impersonation
// extra), so this also pins the impersonation-extra client IP.
func TestClientIP_TrustedPeerHonoursXFF(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "10.0.0.1:5555",
		Header:     http.Header{"X-Forwarded-For": []string{"203.0.113.7"}},
	}

	if got := ClientIP(WithResolvedClient(req, mustCIDRs(t, "10.0.0.0/8"))); got != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want %q", got, "203.0.113.7")
	}
}

// TestClientIP_UnresolvedRequestReportsPeer pins the fallback for a request
// that never passed through WithResolvedClient: the direct peer, which is what
// the contract resolves to when no proxy is trusted, so a caller outside the
// filter chain never sees a forwarded address it did not validate.
func TestClientIP_UnresolvedRequestReportsPeer(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "203.0.113.7:5555",
		Header:     http.Header{"X-Forwarded-For": []string{"1.2.3.4"}},
	}

	if got := ClientIP(req); got != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want %q", got, "203.0.113.7")
	}
}

// TestWithResolvedClient_LeavesCallerRequestUntouched pins that the
// derivation owns its header map: the caller's request still carries exactly
// what arrived, so a filter can report the inbound headers after resolving.
func TestWithResolvedClient_LeavesCallerRequestUntouched(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "203.0.113.7:5555",
		Header: http.Header{
			"X-Forwarded-For": []string{"1.2.3.4"},
			"X-Real-Ip":       []string{"9.9.9.9"},
		},
	}

	out := WithResolvedClient(req, nil)

	if got := out.Header.Get("X-Forwarded-For"); got != "" {
		t.Errorf("derived X-Forwarded-For = %q, want dropped", got)
	}
	if got := req.Header.Get("X-Forwarded-For"); got != "1.2.3.4" {
		t.Errorf("caller's X-Forwarded-For = %q, want untouched 1.2.3.4", got)
	}
	if got := req.Header.Get("X-Real-Ip"); got != "9.9.9.9" {
		t.Errorf("caller's X-Real-Ip = %q, want untouched 9.9.9.9", got)
	}
}

// TestWithResolvedClient pins the trusted-proxy contract as applied to the
// inbound forwarding headers. The final assertion runs the apiserver's own
// utilnet.SourceIPs over the sanitized request — that function is what the
// audit filter uses to fill sourceIPs, so it is the audit-visible outcome that
// is pinned, not just the header rewrite.
func TestWithResolvedClient(t *testing.T) {
	mustCIDRs := func(cidrs ...string) []*net.IPNet { return mustCIDRs(t, cidrs...) }

	tests := map[string]struct {
		trusted      []*net.IPNet
		xff          string
		realIP       string
		expXFF       string
		expOriginal  string
		expSourceIPs []string
	}{
		"no trusted proxies: forwarded headers are stripped": {
			trusted:      nil,
			xff:          "1.2.3.4",
			realIP:       "9.9.9.9",
			expXFF:       "",
			expOriginal:  "1.2.3.4",
			expSourceIPs: []string{"10.0.0.5"},
		},
		"trusted peer: chain collapses to the resolved client": {
			trusted:      mustCIDRs("10.0.0.0/8"),
			xff:          "1.2.3.4, 10.0.0.9",
			expXFF:       "1.2.3.4",
			expOriginal:  "1.2.3.4, 10.0.0.9",
			expSourceIPs: []string{"1.2.3.4", "10.0.0.5"},
		},
		"entirely trusted chain: stripped": {
			trusted:      mustCIDRs("10.0.0.0/8"),
			xff:          "10.0.0.7, 10.0.0.9",
			expXFF:       "",
			expOriginal:  "10.0.0.7, 10.0.0.9",
			expSourceIPs: []string{"10.0.0.5"},
		},
		"malformed hop: stripped": {
			trusted:      mustCIDRs("10.0.0.0/8"),
			xff:          "not-an-ip, 10.0.0.9",
			expXFF:       "",
			expOriginal:  "not-an-ip, 10.0.0.9",
			expSourceIPs: []string{"10.0.0.5"},
		},
		"x-real-ip alone is removed": {
			trusted:      mustCIDRs("10.0.0.0/8"),
			realIP:       "9.9.9.9",
			expXFF:       "",
			expOriginal:  "",
			expSourceIPs: []string{"10.0.0.5"},
		},
		"no forwarding headers: untouched": {
			trusted:      mustCIDRs("10.0.0.0/8"),
			expXFF:       "",
			expOriginal:  "",
			expSourceIPs: []string{"10.0.0.5"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
			req.RemoteAddr = "10.0.0.5:12345"
			if test.xff != "" {
				req.Header.Set("X-Forwarded-For", test.xff)
			}
			if test.realIP != "" {
				req.Header.Set("X-Real-Ip", test.realIP)
			}

			req = WithResolvedClient(req, test.trusted)

			if got := req.Header.Get("X-Forwarded-For"); got != test.expXFF {
				t.Errorf("unexpected X-Forwarded-For after sanitizing, exp=%q got=%q", test.expXFF, got)
			}
			if got := req.Header.Get("X-Real-Ip"); got != "" {
				t.Errorf("X-Real-Ip must always be removed, got %q", got)
			}
			if got := OriginalForwardedFor(req); got != test.expOriginal {
				t.Errorf("unexpected preserved original chain, exp=%q got=%q", test.expOriginal, got)
			}

			var sourceIPs []string
			for _, ip := range utilnet.SourceIPs(req) {
				sourceIPs = append(sourceIPs, ip.String())
			}
			if !reflect.DeepEqual(sourceIPs, test.expSourceIPs) {
				t.Errorf("unexpected audit-visible source IPs, exp=%v got=%v", test.expSourceIPs, sourceIPs)
			}
		})
	}
}

// TestRequestScopedIDAccessors covers the round trip of the correlation-id and
// issuer-name accessors, including the zero value on a request that never
// passed the request-id filter.
func TestRequestScopedIDAccessors(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if got := RequestID(req); got != "" {
		t.Errorf("RequestID on a bare request = %q, want empty", got)
	}
	if got := ClientRequestID(req); got != "" {
		t.Errorf("ClientRequestID on a bare request = %q, want empty", got)
	}
	if got := IssuerName(req); got != "" {
		t.Errorf("IssuerName on a bare request = %q, want empty", got)
	}

	req = WithRequestID(req, "minted-1")
	req = WithClientRequestID(req, "client-1")
	req = WithIssuerName(req, "corp-idp")

	if got := RequestID(req); got != "minted-1" {
		t.Errorf("RequestID = %q, want minted-1", got)
	}
	if got := ClientRequestID(req); got != "client-1" {
		t.Errorf("ClientRequestID = %q, want client-1", got)
	}
	if got := IssuerName(req); got != "corp-idp" {
		t.Errorf("IssuerName = %q, want corp-idp", got)
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
