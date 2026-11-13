// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/authntest"
	"github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview"
	fakesubjectaccessreview "github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview/fake"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

// validDeps returns a Dependencies value with every required field populated,
// and the root logger to build it on, so individual tests can null out one
// field to exercise validation.
func validDeps(t *testing.T) (Dependencies, *slog.Logger) {
	t.Helper()

	ctrl := gomock.NewController(t)
	root, _ := logtest.New(t, 0)

	sar := subjectaccessreview.New(fakesubjectaccessreview.New(nil), subjectaccessreview.Config{MaxHeaderValues: subjectaccessreview.DefaultMaxHeaderValues}, logging.ForComponent(root, logging.ComponentSAR))

	return Dependencies{
		RestConfig:              &rest.Config{Host: "https://kube.example.com"},
		OIDCTokenAuthenticator:  authntest.NewMockToken(ctrl),
		ImpersonationAuthorizer: sar,
		SecureServingInfo:       new(server.SecureServingInfo),
		Auditor:                 newTestAuditor(t, root),
	}, root
}

// TestNewPanicsOnNilLogger pins that the root logger is a required dependency:
// there is no package-level logger to fall back on, and a caller that forgets
// to inject one has a wiring bug, so New panics naming the package rather than
// emitting nothing at runtime.
func TestNewPanicsOnNilLogger(t *testing.T) {
	deps, _ := validDeps(t)
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "proxy:") {
			t.Fatalf("New(nil logger) recovered %v, want a panic naming the proxy package", r)
		}
	}()
	_, _ = New(Config{}, deps, nil)
}

func TestNewValidatesDependencies(t *testing.T) {
	tests := map[string]struct {
		cfg     Config
		mutate  func(d *Dependencies)
		wantErr bool
	}{
		"valid dependencies succeed": {
			mutate:  func(d *Dependencies) {},
			wantErr: false,
		},
		"nil RestConfig fails": {
			mutate:  func(d *Dependencies) { d.RestConfig = nil },
			wantErr: true,
		},
		"nil OIDCTokenAuthenticator fails": {
			mutate:  func(d *Dependencies) { d.OIDCTokenAuthenticator = nil },
			wantErr: true,
		},
		"nil ImpersonationAuthorizer fails": {
			mutate:  func(d *Dependencies) { d.ImpersonationAuthorizer = nil },
			wantErr: true,
		},
		"nil SecureServingInfo fails": {
			mutate:  func(d *Dependencies) { d.SecureServingInfo = nil },
			wantErr: true,
		},
		"nil Auditor fails": {
			mutate:  func(d *Dependencies) { d.Auditor = nil },
			wantErr: true,
		},
		"TokenReview enabled without reviewer fails": {
			cfg:     Config{TokenPassthrough: true},
			mutate:  func(d *Dependencies) { d.TokenReviewer = nil },
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			deps, root := validDeps(t)
			tc.mutate(&deps)

			p, err := New(tc.cfg, deps, root)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("New(%s): expected an error, got nil", name)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%s): unexpected error: %v", name, err)
			}
			if p == nil {
				t.Fatalf("New(%s): expected a Proxy, got nil", name)
			}
		})
	}
}

// TestNewCopiesExtraUserHeaders verifies New copies the caller's
// ExtraUserHeaders map at the construction boundary, so mutating the caller's
// map afterward cannot change proxy behavior.
func TestNewCopiesExtraUserHeaders(t *testing.T) {
	deps, root := validDeps(t)
	src := map[string][]string{"team": {"platform"}}

	p, err := New(Config{ExtraUserHeaders: src}, deps, root)
	if err != nil {
		t.Fatalf("New returned unexpected error: %v", err)
	}

	// Mutate the caller-owned map and slice after construction.
	src["team"][0] = "mutated"
	src["injected"] = []string{"value"}

	got := p.config.ExtraUserHeaders
	if v := got["team"][0]; v != "platform" {
		t.Fatalf("proxy shares slice storage with caller: got %q want %q", v, "platform")
	}
	if _, ok := got["injected"]; ok {
		t.Fatal("proxy shares map storage with caller: injected key leaked into proxy config")
	}
}
