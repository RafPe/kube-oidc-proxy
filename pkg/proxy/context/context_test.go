// Copyright Jetstack Ltd. See LICENSE for details.
package context

import (
	"net"
	"net/http"
	"testing"
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

// TestRemoteAddr_DefaultTrustsNothing verifies the request-level entry point
// uses the direct peer by default and does not honour a forged XFF header.
func TestRemoteAddr_DefaultTrustsNothing(t *testing.T) {
	SetTrustedProxies(nil)
	t.Cleanup(func() { SetTrustedProxies(nil) })

	req := &http.Request{
		RemoteAddr: "203.0.113.7:5555",
		Header:     http.Header{"X-Forwarded-For": []string{"1.2.3.4"}},
	}

	_, got := RemoteAddr(req)
	if got != "203.0.113.7" {
		t.Fatalf("RemoteAddr = %q, want %q", got, "203.0.113.7")
	}
}

// TestRemoteAddr_TrustedPeerHonoursXFF verifies XFF is honoured when the peer is
// a configured trusted proxy. The returned value is exactly what handlers.go
// writes into extra[UserHeaderClientIPKey] (the Remote-Client-IP impersonation
// extra), so this also pins the impersonation-extra client IP.
func TestRemoteAddr_TrustedPeerHonoursXFF(t *testing.T) {
	SetTrustedProxies(mustCIDRs(t, "10.0.0.0/8"))
	t.Cleanup(func() { SetTrustedProxies(nil) })

	req := &http.Request{
		RemoteAddr: "10.0.0.1:5555",
		Header:     http.Header{"X-Forwarded-For": []string{"203.0.113.7"}},
	}

	_, got := RemoteAddr(req)
	if got != "203.0.113.7" {
		t.Fatalf("RemoteAddr = %q, want %q", got, "203.0.113.7")
	}
}

// TestRemoteAddr_CachesResolvedValue verifies the resolved address is cached on
// the request context: a second call returns the cached value even if the
// header or trusted set later changes, keeping the value stable within a
// request.
func TestRemoteAddr_CachesResolvedValue(t *testing.T) {
	SetTrustedProxies(nil)
	t.Cleanup(func() { SetTrustedProxies(nil) })

	req := &http.Request{
		RemoteAddr: "203.0.113.7:5555",
		Header:     http.Header{"X-Forwarded-For": []string{"1.2.3.4"}},
	}

	req, first := RemoteAddr(req)
	if first != "203.0.113.7" {
		t.Fatalf("first RemoteAddr = %q, want %q", first, "203.0.113.7")
	}

	// Change trust config and header; the cached value must not change.
	SetTrustedProxies(mustCIDRs(t, "0.0.0.0/0"))
	req.Header.Set("X-Forwarded-For", "5.6.7.8")

	_, second := RemoteAddr(req)
	if second != first {
		t.Errorf("cached RemoteAddr changed: got %q, want %q", second, first)
	}
}
