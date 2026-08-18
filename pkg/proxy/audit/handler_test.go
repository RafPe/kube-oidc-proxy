// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server"
	apiserveroptions "k8s.io/apiserver/pkg/server/options"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
)

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

	opts := &options.AuditOptions{AuditOptions: apiserveroptions.NewAuditOptions()}
	opts.PolicyFile = policyPath
	opts.LogOptions.Path = logPath

	a, err := New(opts, "0.0.0.0:1234", new(server.SecureServingInfo))
	if err != nil {
		t.Fatalf("creating auditor: %s", err)
	}

	stopCh := make(chan struct{})
	t.Cleanup(func() { close(stopCh) })
	if err := a.Run(stopCh); err != nil {
		t.Fatalf("running audit backend: %s", err)
	}

	return a, logPath
}

// readForbiddenAuditEvents flushes the backend and returns every event written
// to path.
func readForbiddenAuditEvents(t *testing.T, a *Audit, path string) []forbiddenAuditEvent {
	t.Helper()

	if err := a.Shutdown(); err != nil {
		t.Fatalf("shutting down audit backend: %s", err)
	}

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

// TestNewForbiddenHandlerAuditsAuthenticatedIdentity is the regression guard
// against wiring the forbidden handler through WithFailedAuthenticationAudit
// (i.e. reverting it to NewUnauthenticatedHandler). The request authenticated
// successfully and was then refused by the proxy, so the audit record must name
// the identity that was presented and must not read as an authentication
// failure.
func TestNewForbiddenHandlerAuditsAuthenticatedIdentity(t *testing.T) {
	a, logPath := newForbiddenTestAudit(t)

	handler := NewForbiddenHandler(a, func(rw http.ResponseWriter, r *http.Request) {
		http.Error(rw, "forbidden", http.StatusForbidden)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
	// A bearer token is present so that, were the handler wired through
	// WithFailedAuthenticationAudit, the event would carry its
	// "Authentication failed, attempted: bearer" message.
	req.Header.Set("Authorization", "bearer fake-token")
	req = req.WithContext(genericapirequest.WithUser(req.Context(), &authuser.DefaultInfo{
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

// TestNewForbiddenHandlerWithoutAuditor asserts the handler still serves its
// response when no audit backend is configured, matching the nil-safety of
// NewUnauthenticatedHandler.
func TestNewForbiddenHandlerWithoutAuditor(t *testing.T) {
	handler := NewForbiddenHandler(nil, func(rw http.ResponseWriter, r *http.Request) {
		http.Error(rw, "forbidden", http.StatusForbidden)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if got, want := rw.Result().StatusCode, http.StatusForbidden; got != want {
		t.Errorf("unexpected response code, exp=%d got=%d", want, got)
	}
	if got := strings.TrimSpace(rw.Body.String()); got != "forbidden" {
		t.Errorf("unexpected response body, exp=forbidden got=%q", got)
	}
}
