// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
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
			if got := logging.Sanitize(tc.in); got != tc.exp {
				t.Errorf("Sanitize(%q) = %q, want %q", tc.in, got, tc.exp)
			}
		})
	}
}

// TestSanitizePathNilURL keeps the nil-URL guard covered: some call sites
// construct a bare http.Request, and the access record must not panic on one.
func TestSanitizePathNilURL(t *testing.T) {
	if got := sanitizePath(&http.Request{}); got != "" {
		t.Errorf("sanitizePath(bare request) = %q, want %q", got, "")
	}
	if got := sanitizePath(&http.Request{URL: &url.URL{Path: "/a\nb", RawQuery: "token=secret"}}); got != "/a b" {
		t.Errorf("sanitizePath = %q, want %q", got, "/a b")
	}
}

func newAccess(t *testing.T) (*AccessLogger, *logtest.Capture) {
	root, cap := logtest.New(t, 0)
	return NewAccessLogger(logging.ForComponent(root, logging.ComponentRequest), nil), cap
}

func TestLogDecisionDeniedCarriesReasonAndRequestID(t *testing.T) {
	a, cap := newAccess(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/team-a/pods", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	req = proxycontext.WithRequestID(req, "7c1e")

	a.LogDecision(req, Decision{Allowed: false, Reason: "impersonation_denied", AuthMethod: "oidc",
		Inbound: &user.DefaultInfo{Name: "alice"}, TargetKind: "group", TargetName: "system:masters"})

	rec := cap.Only(t, logging.EventRequestAccessDecided)
	for k, want := range map[string]string{
		"event": "AuFail", "decision": "deny", "reason": "impersonation_denied", "request_id": "7c1e",
		"auth_method": "oidc", "http_method": "GET", "src_ip": "1.2.3.4", "path": "/api/v1/namespaces/team-a/pods",
		"target_kind": "group", "target_name": "system:masters", "inbound_user": "alice",
	} {
		if rec.String(k) != want {
			t.Errorf("%s = %q, want %q", k, rec.String(k), want)
		}
	}
}

func TestLogDecisionAllowedIsAuSuccessWithoutReason(t *testing.T) {
	a, cap := newAccess(t)
	req := proxycontext.WithRequestID(httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil), "id")
	a.LogDecision(req, Decision{Allowed: true, AuthMethod: "tokenreview", Inbound: &user.DefaultInfo{Name: "sa"}})
	rec := cap.Only(t, logging.EventRequestAccessDecided)
	if rec.String("event") != "AuSuccess" || rec.String("decision") != "allow" {
		t.Fatalf("%v", rec)
	}
	if _, has := rec["reason"]; has {
		t.Fatal("reason present on an allow")
	}
}

func TestLogDecisionCarriesKubernetesDimensions(t *testing.T) {
	a, cap := newAccess(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/team-a/pods/web-1/log", nil)
	info := &genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "get", APIGroup: "", Resource: "pods",
		Subresource: "log", Namespace: "team-a", Name: "web-1"}
	req = req.WithContext(genericapirequest.WithRequestInfo(req.Context(), info))
	req = proxycontext.WithRequestID(req, "id")
	a.LogDecision(req, Decision{Allowed: true, AuthMethod: "oidc", Inbound: &user.DefaultInfo{Name: "alice"}})
	rec := cap.Only(t, logging.EventRequestAccessDecided)
	if rec.String("k8s_verb") != "get" || rec.String("k8s_resource") != "pods" || rec.String("k8s_subresource") != "log" ||
		rec.String("k8s_namespace") != "team-a" || rec.String("k8s_name") != "web-1" {
		t.Fatalf("%v", rec)
	}
}

func TestGroupsAreCapped(t *testing.T) {
	a, cap := newAccess(t)
	groups := make([]string, 40)
	for i := range groups {
		groups[i] = fmt.Sprintf("g%d", i)
	}
	req := proxycontext.WithRequestID(httptest.NewRequest(http.MethodGet, "/", nil), "id")
	a.LogDecision(req, Decision{Allowed: true, AuthMethod: "oidc", Inbound: &user.DefaultInfo{Name: "a", Groups: groups}})
	rec := cap.Only(t, logging.EventRequestAccessDecided)
	if n, _ := rec.Int("inbound_groups_omitted"); n != 8 {
		t.Fatalf("inbound_groups_omitted = %d, want 8", n)
	}
}

// TestNonResourceRequestHasNoKubernetesDimensions pins that the k8s_* block is
// absent when the request-info resolver did not classify a resource request,
// so a query on k8s_resource never sees a health or discovery path.
func TestNonResourceRequestHasNoKubernetesDimensions(t *testing.T) {
	a, cap := newAccess(t)
	req := proxycontext.WithRequestID(httptest.NewRequest(http.MethodGet, "/healthz", nil), "id")
	req = req.WithContext(genericapirequest.WithRequestInfo(req.Context(),
		&genericapirequest.RequestInfo{IsResourceRequest: false, Path: "/healthz", Verb: "get"}))
	a.LogDecision(req, Decision{Allowed: true, AuthMethod: "none"})
	rec := cap.Only(t, logging.EventRequestAccessDecided)
	for _, key := range []string{"k8s_verb", "k8s_api_group", "k8s_resource", "k8s_namespace", "k8s_name"} {
		if _, has := rec[key]; has {
			t.Errorf("%s present on a non-resource request: %v", key, rec)
		}
	}
}

// TestLogDecisionCarriesRequestCorrelation pins the correlation fields the
// record is queried by: a client-supplied id that was not adopted, and the
// configured issuer name (never the issuer URL).
func TestLogDecisionCarriesRequestCorrelation(t *testing.T) {
	a, cap := newAccess(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
	req = proxycontext.WithRequestID(req, "minted")
	req = proxycontext.WithClientRequestID(req, "from-client")
	req = proxycontext.WithIssuerName(req, "corp")

	a.LogDecision(req, Decision{Allowed: true, AuthMethod: "oidc", Inbound: &user.DefaultInfo{Name: "alice"}})

	rec := cap.Only(t, logging.EventRequestAccessDecided)
	if rec.String("request_id") != "minted" || rec.String("client_request_id") != "from-client" ||
		rec.String("issuer_name") != "corp" {
		t.Fatalf("%v", rec)
	}
}

// TestLogDecisionIsSanitizedAndOmitsClaims verifies issue #55 on the new
// record: output is a single JSON line even with an injection attempt, the
// query string never appears, and arbitrary identity extras are counted rather
// than logged.
func TestLogDecisionIsSanitizedAndOmitsClaims(t *testing.T) {
	a, cap := newAccess(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pods?token=supersecret", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	req = proxycontext.WithRequestID(req, "id")

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

	a.LogDecision(req, Decision{Allowed: true, AuthMethod: "oidc", Inbound: inbound})

	out := strings.TrimRight(cap.Raw(), "\n")
	if strings.Contains(out, "\n") {
		t.Fatalf("log output spans multiple lines, injection not prevented:\n%s", out)
	}
	if strings.Contains(out, "supersecret") {
		t.Errorf("query string leaked into log: %s", out)
	}
	if strings.Contains(out, "secret@example.com") || strings.Contains(out, "do-not-log") {
		t.Errorf("arbitrary extras leaked into log: %s", out)
	}

	rec := cap.Only(t, logging.EventRequestAccessDecided)
	if rec.String("src_ip") != "1.2.3.4" {
		t.Errorf("src_ip = %q, want 1.2.3.4", rec.String("src_ip"))
	}
	if rec.String("path") != "/api/v1/pods" {
		t.Errorf("path = %q, want /api/v1/pods", rec.String("path"))
	}
	if strings.Contains(rec.String("inbound_user"), "\n") {
		t.Errorf("inbound_user still contains newline: %q", rec.String("inbound_user"))
	}
	if n, _ := rec.Int("inbound_extra_omitted"); n != 2 {
		t.Errorf("inbound_extra_omitted = %d, want 2", n)
	}
	extra, ok := rec["inbound_extra"].(map[string]any)
	if !ok {
		t.Fatalf("inbound_extra missing or wrong type: %v", rec["inbound_extra"])
	}
	if _, ok := extra[UserHeaderClientIPKey]; !ok {
		t.Errorf("allowlisted extra %q not logged: %v", UserHeaderClientIPKey, extra)
	}
}

func TestOutboundExtraDoesNotLeakOriginalUserClaims(t *testing.T) {
	a, cap := newAccess(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	req = proxycontext.WithRequestID(req, "id")

	outbound := &user.DefaultInfo{
		Name: "alice",
		Extra: map[string][]string{
			"originaluser.jetstack.io-user":  {"alice"},
			"originaluser.jetstack.io-extra": {`{"tenant":["acme-secret-tenant"]}`},
		},
	}

	a.LogDecision(req, Decision{Allowed: true, AuthMethod: "oidc",
		Inbound: &user.DefaultInfo{Name: "alice"}, Outbound: outbound})

	if strings.Contains(cap.Raw(), "acme-secret-tenant") {
		t.Fatalf("original user extras leaked into the access log:\n%s", cap.Raw())
	}
	rec := cap.Only(t, logging.EventRequestAccessDecided)
	if n, _ := rec.Int("outbound_extra_omitted"); n != 1 {
		t.Fatalf("outbound_extra_omitted = %d, want 1", n)
	}
}

// TestAllowlistedExtraValuesAreNotTruncated pins that the group cap applies to
// groups only. The allowlisted extra arrays are part of the frozen record shape
// and carry no cap, so nothing may silently drop values from them.
func TestAllowlistedExtraValuesAreNotTruncated(t *testing.T) {
	a, cap := newAccess(t)

	values := make([]string, 40)
	for i := range values {
		values[i] = fmt.Sprintf("v%d", i)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	req = proxycontext.WithRequestID(req, "id")

	a.LogDecision(req, Decision{Allowed: true, AuthMethod: "oidc", Inbound: &user.DefaultInfo{
		Name:  "alice",
		Extra: map[string][]string{"originaluser.jetstack.io-groups": values},
	}})

	rec := cap.Only(t, logging.EventRequestAccessDecided)
	extra, ok := rec["inbound_extra"].(map[string]any)
	if !ok {
		t.Fatalf("inbound_extra missing or wrong type: %v", rec["inbound_extra"])
	}
	vals, ok := extra["originaluser.jetstack.io-groups"].([]any)
	if !ok {
		t.Fatalf("allowlisted extra missing or wrong type: %v", extra)
	}
	if len(vals) != 40 {
		t.Errorf("allowlisted extra has %d values, want 40", len(vals))
	}
	if _, has := rec["inbound_groups_omitted"]; has {
		t.Errorf("inbound_groups_omitted present when no group was dropped: %v", rec)
	}
}
