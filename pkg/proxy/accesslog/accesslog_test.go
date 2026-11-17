// Copyright Jetstack Ltd. See LICENSE for details.
package accesslog

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
)

// TestLogDecisionSanitizesThePath pins that the path field carries neither the
// query string, which can hold a credential, nor a control character a client
// could use to forge a second line in a text log.
func TestLogDecisionSanitizesThePath(t *testing.T) {
	a, cap := newAccess(t)
	req := reqctx.WithRequestID(httptest.NewRequest(http.MethodGet, "/a?token=secret", nil), "id")
	req.URL.Path = "/a\nb"

	LogDecision(a, req, Decision{Allowed: true, AuthMethod: "oidc"})

	if got := cap.Only(t, logging.EventRequestAccessDecided).String("path"); got != "/a b" {
		t.Errorf("path = %q, want %q", got, "/a b")
	}
}

func newAccess(t *testing.T) (*slog.Logger, *logtest.Capture) {
	root, cap := logtest.New(t, 0)
	return logging.ForComponent(root, logging.ComponentRequest), cap
}

func TestLogDecisionDeniedCarriesReasonAndRequestID(t *testing.T) {
	a, cap := newAccess(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/team-a/pods", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	req = reqctx.WithRequestID(req, "7c1e")

	LogDecision(a, req, Decision{Allowed: false, Reason: "impersonation_denied", AuthMethod: "oidc",
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
	req := reqctx.WithRequestID(httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil), "id")
	LogDecision(a, req, Decision{Allowed: true, AuthMethod: "tokenreview", Inbound: &user.DefaultInfo{Name: "sa"}})
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
	req = reqctx.WithRequestID(req, "id")
	LogDecision(a, req, Decision{Allowed: true, AuthMethod: "oidc", Inbound: &user.DefaultInfo{Name: "alice"}})
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
	req := reqctx.WithRequestID(httptest.NewRequest(http.MethodGet, "/", nil), "id")
	LogDecision(a, req, Decision{Allowed: true, AuthMethod: "oidc", Inbound: &user.DefaultInfo{Name: "a", Groups: groups}})
	rec := cap.Only(t, logging.EventRequestAccessDecided)
	if n, _ := rec.Int("inbound_groups_omitted"); n != 8 {
		t.Fatalf("inbound_groups_omitted = %d, want 8", n)
	}
}

// TestIdentityWithoutGroupsHasNoGroupsField pins that an identity with no
// groups leaves the _groups field absent, not present as null or [].
func TestIdentityWithoutGroupsHasNoGroupsField(t *testing.T) {
	a, cap := newAccess(t)
	req := reqctx.WithRequestID(httptest.NewRequest(http.MethodGet, "/", nil), "id")
	LogDecision(a, req, Decision{Allowed: true, AuthMethod: "oidc",
		Inbound: &user.DefaultInfo{Name: "alice"}, Impersonated: &user.DefaultInfo{Name: "bob", Groups: []string{}}})
	rec := cap.Only(t, logging.EventRequestAccessDecided)
	for _, field := range []string{"inbound_groups", "outbound_groups"} {
		if v, has := rec[field]; has {
			t.Errorf("%s = %v on an identity with no groups, want the field absent", field, v)
		}
	}
	if rec.String("inbound_user") != "alice" || rec.String("outbound_user") != "bob" {
		t.Errorf("users missing: %v", rec)
	}
}

// TestNonResourceRequestHasNoKubernetesDimensions pins that the k8s_* block is
// absent when the request-info resolver did not classify a resource request,
// so a query on k8s_resource never sees a health or discovery path.
func TestNonResourceRequestHasNoKubernetesDimensions(t *testing.T) {
	a, cap := newAccess(t)
	req := reqctx.WithRequestID(httptest.NewRequest(http.MethodGet, "/healthz", nil), "id")
	req = req.WithContext(genericapirequest.WithRequestInfo(req.Context(),
		&genericapirequest.RequestInfo{IsResourceRequest: false, Path: "/healthz", Verb: "get"}))
	LogDecision(a, req, Decision{Allowed: true, AuthMethod: "none"})
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
	req = reqctx.WithRequestID(req, "minted")
	req = reqctx.WithClientRequestID(req, "from-client")
	req = reqctx.WithIssuerName(req, "corp")

	LogDecision(a, req, Decision{Allowed: true, AuthMethod: "oidc", Inbound: &user.DefaultInfo{Name: "alice"}})

	rec := cap.Only(t, logging.EventRequestAccessDecided)
	if rec.String("request_id") != "minted" || rec.String("client_request_id") != "from-client" ||
		rec.String("issuer_name") != "corp" {
		t.Fatalf("%v", rec)
	}
}

// TestLogDecisionIsSanitizedAndOmitsClaims verifies issue #55 on the new
// record: output is a single JSON line even with an injection attempt, the
// query string never appears, and identity extras are counted rather than
// logged -- including one whose key matches an extra the proxy sets itself,
// because on an identity it is still claim data.
func TestLogDecisionIsSanitizedAndOmitsClaims(t *testing.T) {
	a, cap := newAccess(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pods?token=supersecret", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	req = reqctx.WithRequestID(req, "id")

	inbound := &user.DefaultInfo{
		// Attempt to inject a second log line and a fake field via the username.
		Name:   "evil\nAuSuccess src:[spoofed",
		Groups: []string{"dev", "bad\ngroup"},
		Extra: map[string][]string{
			"Remote-Client-IP":         {"6.6.6.6"},
			"email":                    {"secret@example.com"},
			"authorization-bearer-tok": {"do-not-log"},
		},
	}

	LogDecision(a, req, Decision{Allowed: true, AuthMethod: "oidc", Inbound: inbound})

	out := strings.TrimRight(cap.Raw(), "\n")
	if strings.Contains(out, "\n") {
		t.Fatalf("log output spans multiple lines, injection not prevented:\n%s", out)
	}
	if strings.Contains(out, "supersecret") {
		t.Errorf("query string leaked into log: %s", out)
	}
	if strings.Contains(out, "secret@example.com") || strings.Contains(out, "do-not-log") || strings.Contains(out, "6.6.6.6") {
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
	if n, _ := rec.Int("inbound_extra_omitted"); n != 3 {
		t.Errorf("inbound_extra_omitted = %d, want 3", n)
	}
	if _, has := rec["inbound_extra"]; has {
		t.Errorf("inbound_extra present: identity extras are never logged: %v", rec["inbound_extra"])
	}
}

func TestOutboundExtraDoesNotLeakOriginalUserClaims(t *testing.T) {
	a, cap := newAccess(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	req = reqctx.WithRequestID(req, "id")

	outbound := &user.DefaultInfo{
		Name: "alice",
		Extra: map[string][]string{
			"originaluser.jetstack.io-user":  {"alice"},
			"originaluser.jetstack.io-extra": {`{"tenant":["acme-secret-tenant"]}`},
		},
	}

	LogDecision(a, req, Decision{Allowed: true, AuthMethod: "oidc",
		Inbound: &user.DefaultInfo{Name: "alice"}, Impersonated: outbound})

	if strings.Contains(cap.Raw(), "acme-secret-tenant") {
		t.Fatalf("original user extras leaked into the access log:\n%s", cap.Raw())
	}
	rec := cap.Only(t, logging.EventRequestAccessDecided)
	if n, _ := rec.Int("outbound_extra_omitted"); n != 2 {
		t.Fatalf("outbound_extra_omitted = %d, want 2", n)
	}
}

// TestUIDsAreBounded pins the identity bound on both UID fields. A UID reaches
// the record straight from a token claim, so an unbounded one lets a hostile
// issuer inflate every access record it produces.
func TestUIDsAreBounded(t *testing.T) {
	a, cap := newAccess(t)

	long := strings.Repeat("u", 300)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	req = reqctx.WithRequestID(req, "id")

	LogDecision(a, req, Decision{Allowed: true, AuthMethod: "oidc",
		Inbound:      &user.DefaultInfo{Name: "alice", UID: long},
		Impersonated: &user.DefaultInfo{Name: "alice", UID: long},
	})

	rec := cap.Only(t, logging.EventRequestAccessDecided)
	for _, key := range []string{"inbound_uid", "outbound_uid"} {
		if got := len([]rune(rec.String(key))); got != logging.MaxIdentity {
			t.Errorf("%s is %d runes, want %d", key, got, logging.MaxIdentity)
		}
	}
}
