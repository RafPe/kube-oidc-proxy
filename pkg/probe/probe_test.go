// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// fakeAuthenticator simulates the union authenticator, which routes a token to
// an issuer by its iss claim: issuers listed in notInit have not fetched their
// JWKS yet; every other issuer is initialized and fails ordinary verification
// of the probe token. A per-issuer error may be supplied via override to model
// alternate phrasings and transient failures. Every map is keyed by issuer
// URL.
//
// It is a stateful fake rather than the generated authntest.MockToken on
// purpose: tests flip an issuer from pending to initialized between checks and
// read per-issuer call counts after concurrent probes, which is the behaviour
// under test. A gomock expectation list would have to script every call in
// advance and could not express "however many calls, answer from the current
// state".
type fakeAuthenticator struct {
	mu       sync.Mutex
	notInit  map[string]bool
	override map[string]error
	calls    map[string]int
}

func (f *fakeAuthenticator) AuthenticateToken(_ context.Context, token string) (*authenticator.Response, bool, error) {
	issuerURL := issuerOf(token)
	f.mu.Lock()
	if f.calls == nil {
		f.calls = make(map[string]int)
	}
	f.calls[issuerURL]++
	f.mu.Unlock()

	if err, ok := f.override[issuerURL]; ok {
		return nil, false, err
	}
	if f.notInit[issuerURL] {
		return nil, false, errors.New("oidc: authenticator not initialized")
	}
	return nil, false, errors.New("oidc: verify token: signature invalid")
}

func (f *fakeAuthenticator) callCount(issuerURL string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[issuerURL]
}

// issuerOf returns the iss claim of a probe token, or "" for a token that is
// not one.
func issuerOf(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	return claims.Issuer
}

// newTestServerWithAuthenticator builds an unstarted Server probing issuers
// through authn. It reports through a discarding logger; a test that asserts
// on records uses newTestServerWithLogger. An unstarted server needs no
// address: check is driven directly.
func newTestServerWithAuthenticator(t testing.TB, requireAll bool, authn authenticator.Token, issuerURLs ...string) *Server {
	t.Helper()
	return newTestServerWithRoot(t, slog.New(slog.DiscardHandler), requireAll, authn, issuerURLs...)
}

func newTestServerWithRoot(t testing.TB, root *slog.Logger, requireAll bool, authn authenticator.Token, issuerURLs ...string) *Server {
	t.Helper()
	return NewServer(Config{IssuerURLs: issuerURLs, Mode: ReadinessModeFor(requireAll), Authenticator: authn}, root)
}

func newTestServer(t testing.TB, requireAll bool, notInit map[string]bool, issuerURLs ...string) *Server {
	t.Helper()
	return newTestServerWithAuthenticator(t, requireAll, &fakeAuthenticator{notInit: notInit}, issuerURLs...)
}

// newTestServerWithLogger builds a Server reporting through root.
func newTestServerWithLogger(t testing.TB, root *slog.Logger, requireAll bool, notInit map[string]bool, issuerURLs ...string) *Server {
	t.Helper()
	return newTestServerWithRoot(t, root, requireAll, &fakeAuthenticator{notInit: notInit}, issuerURLs...)
}

func TestCheckReadiness(t *testing.T) {
	issuerA := "https://a.example.com"
	issuerB := "https://b.example.com"

	tests := []struct {
		name       string
		requireAll bool
		notInit    map[string]bool
		wantReady  bool
	}{
		{
			name:       "default mode: one of two initialized is ready",
			requireAll: false,
			notInit:    map[string]bool{issuerB: true},
			wantReady:  true,
		},
		{
			name:       "default mode: none initialized is not ready",
			requireAll: false,
			notInit:    map[string]bool{issuerA: true, issuerB: true},
			wantReady:  false,
		},
		{
			name:       "require-all: one pending is not ready",
			requireAll: true,
			notInit:    map[string]bool{issuerB: true},
			wantReady:  false,
		},
		{
			name:       "require-all: all initialized is ready",
			requireAll: true,
			notInit:    map[string]bool{},
			wantReady:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestServer(t, tc.requireAll, tc.notInit, issuerA, issuerB)
			// This table covers issuer readiness, so open the serving gate;
			// TestCheckNotReadyBeforeServing covers the gate itself.
			h.SetServing()
			err := h.check()
			if tc.wantReady && err != nil {
				t.Fatalf("expected ready, got error: %v", err)
			}
			if !tc.wantReady && err == nil {
				t.Fatal("expected not ready, got nil error")
			}
		})
	}
}

// TestCheckNotReadyBeforeServing verifies the serving gate: even with every
// issuer initialized, readiness stays false until the proxy is actually
// serving. An initialized issuer on a process that is not yet answering
// requests is not readiness.
func TestCheckNotReadyBeforeServing(t *testing.T) {
	issuerA := "https://a.example.com"
	h := newTestServer(t, true, nil, issuerA)

	err := h.check()
	if err == nil {
		t.Fatal("expected not-ready before the proxy is serving, got nil")
	}
	if !strings.Contains(err.Error(), "serving") {
		t.Fatalf("expected the error to name the serving condition, got: %v", err)
	}
	if h.ready {
		t.Fatal("readiness must not latch before the proxy is serving")
	}
}

// TestCheckReadyAfterServing verifies the gate opens: the same health check
// that reports not-ready before serving reports ready once SetServing is
// called, so the gate delays readiness rather than blocking it permanently.
func TestCheckReadyAfterServing(t *testing.T) {
	issuerA := "https://a.example.com"
	h := newTestServer(t, true, nil, issuerA)

	if err := h.check(); err == nil {
		t.Fatal("expected not-ready before the proxy is serving, got nil")
	}

	h.SetServing()
	if err := h.check(); err != nil {
		t.Fatalf("expected ready once serving with the issuer initialized, got: %v", err)
	}
}

// TestReadyEndpointReportsNotServing verifies the gate is visible over HTTP:
// /ready answers 503 and names the serving condition, so an operator reading
// the probe response can tell why the pod is held back.
func TestReadyEndpointReportsNotServing(t *testing.T) {
	h := newTestServer(t, false, nil,
		"https://a.example.com")
	handler := h.handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /ready before serving: got %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), "serving") {
		t.Fatalf("expected the body to name the serving condition, got: %q", rec.Body.String())
	}

	// Liveness is not gated: the process is alive well before it serves, and
	// gating it would invite the kubelet to restart the pod during startup.
	liveRec := httptest.NewRecorder()
	handler.ServeHTTP(liveRec, httptest.NewRequest(http.MethodGet, "/live", nil))
	if liveRec.Code != http.StatusOK {
		t.Fatalf("GET /live before serving: got %d, want %d", liveRec.Code, http.StatusOK)
	}

	// Once serving, the same endpoint reports ready.
	h.SetServing()
	readyRec := httptest.NewRecorder()
	handler.ServeHTTP(readyRec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if readyRec.Code != http.StatusOK {
		t.Fatalf("GET /ready after serving: got %d, want %d", readyRec.Code, http.StatusOK)
	}
}

func TestCheckReadinessIsSticky(t *testing.T) {
	issuerA := "https://a.example.com"
	notInit := map[string]bool{}
	h := newTestServer(t, false, notInit, issuerA)
	h.SetServing()

	if err := h.check(); err != nil {
		t.Fatalf("expected ready, got: %v", err)
	}

	// Simulate the issuer regressing to uninitialized: readiness must stick.
	notInit[issuerA] = true
	if err := h.check(); err != nil {
		t.Fatalf("expected readiness to be sticky, got: %v", err)
	}
}

// TestCheckContinuesProbingPendingAfterLatch verifies that once readiness
// latches (default mode, one of two issuers initialized), subsequent Check
// calls still return nil AND still probe the still-pending issuer so it can
// transition to initialized and be logged, while the already-initialized
// issuer is not re-probed.
func TestCheckContinuesProbingPendingAfterLatch(t *testing.T) {
	issuerA := "https://a.example.com"
	issuerB := "https://b.example.com"

	notInit := map[string]bool{issuerB: true}
	h := newTestServer(t, false, notInit, issuerA, issuerB)
	h.SetServing()
	fake := h.oidcAuthenticator.(*fakeAuthenticator)

	if err := h.check(); err != nil {
		t.Fatalf("expected ready (issuer A initialized), got: %v", err)
	}
	if !h.ready {
		t.Fatal("expected readiness to have latched")
	}

	aCallsAfterFirst := fake.callCount(issuerA)
	bCallsAfterFirst := fake.callCount(issuerB)
	if aCallsAfterFirst != 1 || bCallsAfterFirst != 1 {
		t.Fatalf("expected 1 call each after first Check, got a=%d b=%d", aCallsAfterFirst, bCallsAfterFirst)
	}

	// Second Check: readiness already latched, so it must return nil
	// regardless of issuer B still being pending, but issuer B must still
	// be probed (call count increases) while issuer A (already
	// initialized) must not be re-probed.
	if err := h.check(); err != nil {
		t.Fatalf("expected nil error once latched even with issuer B pending, got: %v", err)
	}

	if got := fake.callCount(issuerA); got != aCallsAfterFirst {
		t.Fatalf("expected initialized issuer A not to be re-probed, call count changed from %d to %d", aCallsAfterFirst, got)
	}
	if got := fake.callCount(issuerB); got <= bCallsAfterFirst {
		t.Fatalf("expected pending issuer B to still be probed, call count did not increase (still %d)", got)
	}

	// Now let issuer B initialize and confirm the transition is picked up
	// and it is subsequently no longer re-probed either.
	delete(notInit, issuerB)
	if err := h.check(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	bCallsAfterInit := fake.callCount(issuerB)

	if err := h.check(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if got := fake.callCount(issuerB); got != bCallsAfterInit {
		t.Fatalf("expected issuer B not to be re-probed once initialized, call count changed from %d to %d", bCallsAfterInit, got)
	}
}

// TestCheckAlternatePhrasingKeepsPending verifies that the alternate upstream
// wording "... is not initialized" is still recognised as pending and does not
// falsely latch readiness.
func TestCheckAlternatePhrasingKeepsPending(t *testing.T) {
	issuerA := "https://a.example.com"

	authn := &fakeAuthenticator{
		override: map[string]error{
			issuerA: errors.New("oidc: authenticator for issuer is not initialized"),
		},
	}
	h := newTestServerWithAuthenticator(t, true, authn, issuerA)
	h.SetServing()

	if err := h.check(); err == nil {
		t.Fatal("expected not-ready for alternate 'is not initialized' phrasing, got nil")
	}
	if h.ready {
		t.Fatal("readiness must not latch while the only issuer is uninitialized")
	}
	if h.initialized[issuerA] {
		t.Fatal("issuer must not be marked initialized for a 'not initialized' error")
	}
}

// TestCheckTransientErrorDoesNotLatch verifies that a transient network/timeout
// error leaves the issuer pending instead of being mistaken for a fetched JWKS
// (which would falsely latch readiness).
func TestCheckTransientErrorDoesNotLatch(t *testing.T) {
	issuerA := "https://a.example.com"

	tests := map[string]error{
		"context deadline": context.DeadlineExceeded,
		"connection refused": fmt.Errorf(`Get "https://a.example.com/.well-known/openid-configuration": %w`,
			&net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}),
		"no such host": fmt.Errorf(`Get "https://a.example.com/.well-known/openid-configuration": %w`,
			&net.DNSError{Err: "no such host", Name: "a.example.com", IsNotFound: true}),
		"net timeout wrapped": &net.OpError{Op: "dial", Err: timeoutError{}},
	}

	for name, retErr := range tests {
		t.Run(name, func(t *testing.T) {
			authn := &fakeAuthenticator{override: map[string]error{issuerA: retErr}}
			h := newTestServerWithAuthenticator(t, true, authn, issuerA)
			h.SetServing()

			if err := h.check(); err == nil {
				t.Fatal("expected not-ready for transient error, got nil")
			}
			if h.ready {
				t.Fatal("readiness must not latch on a transient error")
			}
			if h.initialized[issuerA] {
				t.Fatal("issuer must not be marked initialized on a transient error")
			}
		})
	}
}

// TestHandlerRejectsNonGET verifies the readiness/liveness endpoints answer GET
// but reject other methods with 405.
func TestHandlerRejectsNonGET(t *testing.T) {
	h := newTestServer(t, false, nil,
		"https://a.example.com")
	// Serving, so GET /ready exercises the readiness path rather than the gate.
	h.SetServing()
	handler := h.handler()

	for _, path := range []string{"/live", "/ready"} {
		getReq := httptest.NewRequest(http.MethodGet, path, nil)
		getRec := httptest.NewRecorder()
		handler.ServeHTTP(getRec, getReq)
		if getRec.Code == http.StatusMethodNotAllowed {
			t.Fatalf("GET %s: unexpected 405", path)
		}

		postReq := httptest.NewRequest(http.MethodPost, path, nil)
		postRec := httptest.NewRecorder()
		handler.ServeHTTP(postRec, postReq)
		if postRec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s: got %d, want %d", path, postRec.Code, http.StatusMethodNotAllowed)
		}
	}
}

// timeoutError is a net.Error whose Timeout reports true, modelling a wrapped
// i/o timeout surfaced through errors.As.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestNewIssuerReadinessNamesTheIssuer pins what the probe token must carry:
// the authenticator routes a token to an issuer by its iss claim, so a token
// naming a different issuer would probe the wrong one.
func TestNewIssuerReadinessNamesTheIssuer(t *testing.T) {
	const issuerURL = "https://issuer.example.com/realm"
	r := newIssuerReadiness(issuerURL)
	if r.issuerURL != issuerURL {
		t.Fatalf("issuerURL = %q, want %q", r.issuerURL, issuerURL)
	}

	// Decoded by hand, as the probe builds it: a JOSE library here would only
	// check what the three asserts below already pin.
	parts := strings.Split(r.fakeJWT, ".")
	if len(parts) != 3 {
		t.Fatalf("probe token has %d parts, want 3: %q", len(parts), r.fakeJWT)
	}
	decode := func(part string, into any) {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatalf("probe token part %q is not base64url: %v", part, err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatalf("probe token part %q is not JSON: %v", raw, err)
		}
	}

	var header map[string]string
	decode(parts[0], &header)
	if header["alg"] != "HS256" || header["typ"] != "JWT" {
		t.Fatalf("header = %v, want alg=HS256 typ=JWT", header)
	}

	var claims struct {
		Issuer string `json:"iss"`
	}
	decode(parts[1], &claims)
	if claims.Issuer != issuerURL {
		t.Fatalf("iss = %q, want %q", claims.Issuer, issuerURL)
	}

	mac := hmac.New(sha256.New, fakeJWTKey)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)); parts[2] != want {
		t.Fatalf("signature = %q, want the HS256 MAC %q", parts[2], want)
	}
}
