// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"errors"
	"testing"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/heptiolabs/healthcheck"
)

// fakeAuther simulates the union authenticator: tokens listed in notInit
// hit an issuer whose JWKS is not yet fetched; every other token reaches
// an initialized issuer and fails ordinary verification.
type fakeAuther struct {
	notInit map[string]bool
}

func (f *fakeAuther) AuthenticateToken(_ context.Context, token string) (*authenticator.Response, bool, error) {
	if f.notInit[token] {
		return nil, false, errors.New("oidc: authenticator not initialized")
	}
	return nil, false, errors.New("oidc: verify token: signature invalid")
}

func newTestHealthCheck(requireAll bool, notInit map[string]bool, issuers ...IssuerReadiness) *HealthCheck {
	return &HealthCheck{
		handler:    healthcheck.NewHandler(),
		oidcAuther: &fakeAuther{notInit: notInit},
		issuers:    issuers,
		requireAll: requireAll,
	}
}

func TestCheckReadiness(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	issuerB := IssuerReadiness{IssuerURL: "https://b.example.com", FakeJWT: "jwt-b"}

	tests := []struct {
		name       string
		requireAll bool
		notInit    map[string]bool
		wantReady  bool
	}{
		{
			name:       "default mode: one of two initialized is ready",
			requireAll: false,
			notInit:    map[string]bool{"jwt-b": true},
			wantReady:  true,
		},
		{
			name:       "default mode: none initialized is not ready",
			requireAll: false,
			notInit:    map[string]bool{"jwt-a": true, "jwt-b": true},
			wantReady:  false,
		},
		{
			name:       "require-all: one pending is not ready",
			requireAll: true,
			notInit:    map[string]bool{"jwt-b": true},
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
			h := newTestHealthCheck(tc.requireAll, tc.notInit, issuerA, issuerB)
			err := h.Check()
			if tc.wantReady && err != nil {
				t.Fatalf("expected ready, got error: %v", err)
			}
			if !tc.wantReady && err == nil {
				t.Fatal("expected not ready, got nil error")
			}
		})
	}
}

func TestCheckReadinessIsSticky(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	notInit := map[string]bool{}
	h := newTestHealthCheck(false, notInit, issuerA)

	if err := h.Check(); err != nil {
		t.Fatalf("expected ready, got: %v", err)
	}

	// Simulate the issuer regressing to uninitialized: readiness must stick.
	notInit["jwt-a"] = true
	if err := h.Check(); err != nil {
		t.Fatalf("expected readiness to be sticky, got: %v", err)
	}
}
