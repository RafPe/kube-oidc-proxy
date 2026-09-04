// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"

	proxycontext "github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
)

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	return n
}

// TestResolveClientIP exercises the trusted-proxy / client-IP contract for
// issue #56: forwarded headers are honoured only when the immediate peer is a
// trusted proxy, across multiple hops, malformed values, IPv4 and IPv6.
func TestResolveClientIP(t *testing.T) {
	trustedV4 := []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}
	trustedMixed := []*net.IPNet{mustCIDR(t, "10.0.0.0/8"), mustCIDR(t, "fd00::/8")}

	tests := map[string]struct {
		remoteAddr string
		xff        string
		trusted    []*net.IPNet
		exp        string
	}{
		"no trusted proxies ignores XFF": {
			remoteAddr: "10.0.0.1:1234",
			xff:        "1.2.3.4",
			trusted:    nil,
			exp:        "10.0.0.1",
		},
		"untrusted peer cannot spoof via XFF": {
			remoteAddr: "203.0.113.9:5555",
			xff:        "1.2.3.4",
			trusted:    trustedV4,
			exp:        "203.0.113.9",
		},
		"trusted peer single hop": {
			remoteAddr: "10.0.0.1:1234",
			xff:        "1.2.3.4",
			trusted:    trustedV4,
			exp:        "1.2.3.4",
		},
		"trusted peer multiple hops takes first untrusted from the right": {
			remoteAddr: "10.0.0.1:1234",
			xff:        "1.2.3.4, 10.0.0.9, 10.0.0.8",
			trusted:    trustedV4,
			exp:        "1.2.3.4",
		},
		"trusted peer all hops trusted falls back to peer": {
			remoteAddr: "10.0.0.1:1234",
			xff:        "10.0.0.7, 10.0.0.8",
			trusted:    trustedV4,
			exp:        "10.0.0.1",
		},
		"malformed hop stops the walk": {
			remoteAddr: "10.0.0.1:1234",
			xff:        "1.2.3.4, garbage, 10.0.0.8",
			trusted:    trustedV4,
			exp:        "10.0.0.1",
		},
		"empty XFF returns peer": {
			remoteAddr: "10.0.0.1:1234",
			xff:        "",
			trusted:    trustedV4,
			exp:        "10.0.0.1",
		},
		"ipv6 trusted peer and client": {
			remoteAddr: "[fd00::1]:443",
			xff:        "2001:db8::1, fd00::2",
			trusted:    trustedMixed,
			exp:        "2001:db8::1",
		},
		"ipv6 peer without port": {
			remoteAddr: "fd00::1",
			xff:        "2001:db8::1",
			trusted:    trustedMixed,
			exp:        "2001:db8::1",
		},
		"empty remote addr": {
			remoteAddr: "",
			xff:        "1.2.3.4",
			trusted:    trustedV4,
			exp:        "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := resolveClientIP(tc.remoteAddr, tc.xff, tc.trusted)
			if got != tc.exp {
				t.Errorf("resolveClientIP(%q, %q) = %q, want %q", tc.remoteAddr, tc.xff, got, tc.exp)
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
			if got := proxycontext.PeerHost(tc.in); got != tc.exp {
				t.Errorf("PeerHost(%q) = %q, want %q", tc.in, got, tc.exp)
			}
		})
	}
}

func TestSanitize(t *testing.T) {
	tests := map[string]struct{ in, exp string }{
		"plain":            {"alice@example.com", "alice@example.com"},
		"newline to space": {"a\nb", "a b"},
		"crlf to spaces":   {"a\r\nb", "a  b"},
		"tab to space":     {"a\tb", "a b"},
		"drops control":    {"a\x00\x1bb", "ab"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := sanitize(tc.in); got != tc.exp {
				t.Errorf("sanitize(%q) = %q, want %q", tc.in, got, tc.exp)
			}
		})
	}
}

// captureLogger redirects the package logger to an in-memory JSON buffer and
// returns the buffer plus a restore func.
func captureLogger(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	prev := logger
	buf := &bytes.Buffer{}
	logger = slog.New(slog.NewJSONHandler(buf, nil))
	return buf, func() { logger = prev }
}

// TestLogSuccessfulRequestStructured verifies issue #55: output is structured
// JSON, a single line per record even with an injection attempt, arbitrary
// identity extras are omitted (with a count), and allowlisted extras are kept.
func TestLogSuccessfulRequestStructured(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	req := &http.Request{
		RemoteAddr: "1.2.3.4:5555",
		URL:        &url.URL{Path: "/api/v1/pods", RawQuery: "token=supersecret"},
		Header:     http.Header{},
	}

	inbound := &user.DefaultInfo{
		// Attempt to inject a second log line and a fake field via the username.
		Name:   "evil\nAuSuccess src:[spoofed",
		Groups: []string{"dev", "bad\ngroup"},
		Extra: map[string][]string{
			UserHeaderClientIPKey:      {"1.2.3.4"},
			"email":                    {"secret@example.com"},
			"authorization-bearer-tok": {"do-not-log"},
		},
	}

	LogSuccessfulRequest(req, inbound, nil)

	out := strings.TrimRight(buf.String(), "\n")
	if strings.Contains(out, "\n") {
		t.Fatalf("log output spans multiple lines, injection not prevented:\n%s", out)
	}

	var rec map[string]any
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}

	if rec["event"] != "AuSuccess" {
		t.Errorf("event = %v, want AuSuccess", rec["event"])
	}
	if rec["src_ip"] != "1.2.3.4" {
		t.Errorf("src_ip = %v, want 1.2.3.4", rec["src_ip"])
	}
	// Path only, query string must not be logged.
	if rec["path"] != "/api/v1/pods" {
		t.Errorf("path = %v, want /api/v1/pods", rec["path"])
	}
	if strings.Contains(out, "supersecret") {
		t.Errorf("query string leaked into log: %s", out)
	}
	// Username newline was neutralised.
	if name, _ := rec["inbound_user"].(string); strings.Contains(name, "\n") {
		t.Errorf("inbound_user still contains newline: %q", name)
	}
	// Arbitrary claim extras must be omitted, not logged.
	if strings.Contains(out, "secret@example.com") || strings.Contains(out, "do-not-log") {
		t.Errorf("arbitrary extras leaked into log: %s", out)
	}
	if omitted, ok := rec["inbound_extra_omitted"].(float64); !ok || omitted != 2 {
		t.Errorf("inbound_extra_omitted = %v, want 2", rec["inbound_extra_omitted"])
	}
	// Allowlisted extra must be present.
	extra, ok := rec["inbound_extra"].(map[string]any)
	if !ok {
		t.Fatalf("inbound_extra missing or wrong type: %v", rec["inbound_extra"])
	}
	if _, ok := extra[UserHeaderClientIPKey]; !ok {
		t.Errorf("allowlisted extra %q not logged: %v", UserHeaderClientIPKey, extra)
	}
}

func TestLogFailedRequestNilURL(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	// Bare request as constructed by some call sites: no URL, no RemoteAddr.
	req := &http.Request{Header: http.Header{}}

	// Must not panic on nil URL / empty RemoteAddr.
	LogFailedRequest(req)

	out := strings.TrimRight(buf.String(), "\n")
	var rec map[string]any
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if rec["event"] != "AuFail" {
		t.Errorf("event = %v, want AuFail", rec["event"])
	}
}

func TestOutboundExtraDoesNotLeakOriginalUserClaims(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	req := &http.Request{RemoteAddr: "1.2.3.4:5555", URL: &url.URL{Path: "/api/v1/pods"}, Header: http.Header{}}
	inbound := &user.DefaultInfo{Name: "alice"}
	outbound := &user.DefaultInfo{
		Name: "alice",
		Extra: map[string][]string{
			"originaluser.jetstack.io-user":  {"alice"},
			"originaluser.jetstack.io-extra": {`{"tenant":["acme-secret-tenant"]}`},
		},
	}

	LogSuccessfulRequest(req, inbound, outbound)

	if strings.Contains(buf.String(), "acme-secret-tenant") {
		t.Fatalf("original user extras leaked into the access log:\n%s", buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["outbound_extra_omitted"] != float64(1) {
		t.Fatalf("outbound_extra_omitted = %v, want 1", rec["outbound_extra_omitted"])
	}
}
