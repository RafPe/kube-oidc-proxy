// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server"
	apiserveroptions "k8s.io/apiserver/pkg/server/options"
)

// TestWithRequestInfoResolvesCoreGroupAsResourceRequest pins
// LegacyAPIGroupPrefixes. Without it every /api request parses as a
// non-resource request whose verb is the lowercased HTTP method, which would
// silently collapse the k8s_verb metric label to "other" and the scope label
// to "none" for the whole core group.
func TestWithRequestInfoResolvesCoreGroupAsResourceRequest(t *testing.T) {
	a, err := New(Config{ExternalAddress: "0.0.0.0:1234", SecureServing: new(server.SecureServingInfo)}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		method, path      string
		wantVerb, wantRes string
		wantNamespace     string
		wantResource      bool
	}{
		"core group list in a namespace": {
			method: http.MethodGet, path: "/api/v1/namespaces/team-a/pods",
			wantVerb: "list", wantRes: "pods", wantNamespace: "team-a", wantResource: true,
		},
		"core group watch": {
			method: http.MethodGet, path: "/api/v1/pods?watch=true",
			wantVerb: "watch", wantRes: "pods", wantResource: true,
		},
		"named group create": {
			method: http.MethodPost, path: "/apis/apps/v1/namespaces/team-a/deployments",
			wantVerb: "create", wantRes: "deployments", wantNamespace: "team-a", wantResource: true,
		},
		"non-resource path keeps the raw method": {
			method: http.MethodPost, path: "/healthz",
			wantVerb: "post", wantResource: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var got *request.RequestInfo
			h := a.WithRequestInfo(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got, _ = request.RequestInfoFrom(r.Context())
			}))
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.path, nil))
			if got == nil {
				t.Fatal("no RequestInfo on the context")
			}
			if got.IsResourceRequest != tc.wantResource || got.Verb != tc.wantVerb ||
				got.Resource != tc.wantRes || got.Namespace != tc.wantNamespace {
				t.Fatalf("got %+v, want resource=%v verb=%q resource=%q namespace=%q",
					got, tc.wantResource, tc.wantVerb, tc.wantRes, tc.wantNamespace)
			}
		})
	}
}

// forbiddenAuditEvent is the subset of an audit.k8s.io/v1 Event this test
// asserts on. Decoding into a local struct keeps the assertions independent of
// the apiserver's internal/external event conversions.
type forbiddenAuditEvent struct {
	Stage string `json:"stage"`
	User  struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"user"`
	ResponseStatus *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"responseStatus"`
}

// forbiddenAuditPolicy is a Metadata-level policy for every request.
// RequestReceived is omitted so the backend emits exactly one event per
// request, keeping the assertions unambiguous.
const forbiddenAuditPolicy = `apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - RequestReceived
rules:
  - level: Metadata
`

// newForbiddenTestAudit builds a real Audit backed by a file log backend and a
// Metadata policy, returning it alongside the path the events are written to.
func newForbiddenTestAudit(t *testing.T) (*Audit, string) {
	t.Helper()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(forbiddenAuditPolicy), 0600); err != nil {
		t.Fatalf("writing audit policy: %s", err)
	}
	logPath := filepath.Join(dir, "audit.log")

	opts := apiserveroptions.NewAuditOptions()
	opts.PolicyFile = policyPath
	opts.LogOptions.Path = logPath

	a, err := New(Config{Options: opts, ExternalAddress: "0.0.0.0:1234", SecureServing: new(server.SecureServingInfo)}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("creating auditor: %s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := a.Start(ctx); err != nil {
		t.Fatalf("running audit backend: %s", err)
	}

	return a, logPath
}

// readForbiddenAuditEvents flushes the backend and returns every event written
// to path.
func readForbiddenAuditEvents(t *testing.T, a *Audit, path string) []forbiddenAuditEvent {
	t.Helper()

	a.Shutdown()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log %q: %s", path, err)
	}

	var events []forbiddenAuditEvent
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var event forbiddenAuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decoding audit event %q: %s", line, err)
		}
		events = append(events, event)
	}

	return events
}

// TestWithRequestAuditsAuthenticatedIdentity is the regression guard against
// auditing a refusal of an authenticated request through the
// failed-authentication chain. The request authenticated
// successfully and was then refused by the proxy, so the audit record must name
// the identity that was presented and must not read as an authentication
// failure.
//
// The assertions are deliberately confined to what this handler decides: the
// stage, the identity, the status code, and the absence of an
// authentication-failure message. The event's verb and objectRef are not
// asserted because they are decided by the RequestInfo resolver, so they move
// with its configuration — a core-group path like the one below is classified
// as a non-resource request (verb "get", no objectRef) unless the resolver is
// given the legacy API group prefixes, which turns it into a resource request
// (verb "list", objectRef present). Assert on those only against the resolver
// this package actually builds.
func TestWithRequestAuditsAuthenticatedIdentity(t *testing.T) {
	a, logPath := newForbiddenTestAudit(t)

	handler := a.WithRequestInfo(a.WithRequest(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Error(rw, "forbidden", http.StatusForbidden)
	})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
	// A bearer token is present so that, were the refusal audited through
	// WithFailedAuthentication, the event would carry its
	// "Authentication failed, attempted: bearer" message.
	req.Header.Set("Authorization", "bearer fake-token")
	req = req.WithContext(request.WithUser(req.Context(), &authuser.DefaultInfo{
		Name:   "alice",
		Groups: []string{"system:masters"},
	}))

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if got, want := rw.Result().StatusCode, http.StatusForbidden; got != want {
		t.Errorf("unexpected response code, exp=%d got=%d", want, got)
	}

	events := readForbiddenAuditEvents(t, a, logPath)
	if len(events) != 1 {
		t.Fatalf("expected exactly one audit event, got %d: %+v", len(events), events)
	}
	event := events[0]

	if event.Stage != "ResponseComplete" {
		t.Errorf("expected a ResponseComplete audit event, got stage %q", event.Stage)
	}

	// The regression guard: the authenticated identity, not an empty user.
	if event.User.Username != "alice" {
		t.Errorf("audit event does not carry the authenticated user, exp=alice got=%q", event.User.Username)
	}
	if len(event.User.Groups) != 1 || event.User.Groups[0] != "system:masters" {
		t.Errorf("audit event does not carry the authenticated groups, exp=[system:masters] got=%v", event.User.Groups)
	}

	if event.ResponseStatus == nil {
		t.Fatal("audit event has no responseStatus")
	}
	if got, want := event.ResponseStatus.Code, http.StatusForbidden; got != want {
		t.Errorf("unexpected audited response code, exp=%d got=%d", want, got)
	}

	// Not an authentication-failure record.
	if strings.Contains(event.ResponseStatus.Message, "Authentication failed") {
		t.Errorf("audit event reads as an authentication failure: %q", event.ResponseStatus.Message)
	}
}

// TestWithFailedAuthenticationAuditsFailedAuthentication is the regression
// guard for the missing WithAuditInit in the failed-authentication chain
// (TremoloSecurity/kube-oidc-proxy#92). Without an initialised audit context
// the failed-authentication filter finds auditing disabled and a rejected
// request leaves no trace in the audit log at all — the exact case an audit
// log exists for.
//
// Assertions are confined to what this chain decides: that exactly one event
// is written, at ResponseStarted (the stage the failed-auth filter's decorated
// response writer records on WriteHeader), carrying the 401 and the
// authentication-failure message, with no authenticated identity. Verb and
// objectRef are the RequestInfo resolver's decision and are covered elsewhere.
func TestWithFailedAuthenticationAuditsFailedAuthentication(t *testing.T) {
	a, logPath := newForbiddenTestAudit(t)

	handler := a.WithRequestInfo(a.WithFailedAuthentication(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusUnauthorized)
	})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/kube-system/pods", nil)
	req.Header.Set("Authorization", "bearer some-invalid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	events := readForbiddenAuditEvents(t, a, logPath)
	if len(events) != 1 {
		t.Fatalf("expected exactly one audit event for a failed authentication, got %d: %+v", len(events), events)
	}

	event := events[0]
	if event.Stage != "ResponseStarted" {
		t.Errorf("expected stage ResponseStarted, got %q", event.Stage)
	}
	if event.User.Username != "" {
		t.Errorf("failed authentication must not record an identity, got %q", event.User.Username)
	}
	if event.ResponseStatus == nil {
		t.Fatalf("expected a responseStatus on the event, got none")
	}
	if event.ResponseStatus.Code != http.StatusUnauthorized {
		t.Errorf("expected responseStatus code 401, got %d", event.ResponseStatus.Code)
	}
	if !strings.Contains(event.ResponseStatus.Message, "Authentication failed, attempted: bearer") {
		t.Errorf("expected the authentication-failure message naming the attempted method, got %q", event.ResponseStatus.Message)
	}
}
