// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"strings"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/mocks"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	fakesubjectaccessreview "github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview/fake"
)

// validDeps returns a Dependencies value with every required field populated,
// so individual tests can null out one field to exercise validation.
func validDeps(t *testing.T) Dependencies {
	t.Helper()

	ctrl := gomock.NewController(t)
	root, _ := logtest.New(t, 0)

	sar, err := subjectaccessreview.New(fakesubjectaccessreview.New(nil), subjectaccessreview.DefaultTimeout, 0, 0,
		subjectaccessreview.DefaultMaxHeaderValues, logging.ForComponent(root, logging.ComponentSAR))
	if err != nil {
		t.Fatalf("building SubjectAccessReview: %v", err)
	}

	return Dependencies{
		Logger:                root,
		RestConfig:            &rest.Config{Host: "https://kube.example.com"},
		TokenAuthenticator:    mocks.NewMockToken(ctrl),
		AuditOptions:          new(options.AuditOptions),
		SubjectAccessReviewer: sar,
		SecureServingInfo:     new(server.SecureServingInfo),
		// ExternalAddress must be set: audit.New derives the audit server's
		// external address from it and fatals when it is empty with no listener.
		Config: &Config{ExternalAddress: "0.0.0.0:1234"},
	}
}

// TestNewRequiresLogger pins that the root logger is a required dependency:
// there is no package-level logger to fall back on, so a caller that forgets to
// inject one must fail at construction rather than emit nothing at runtime.
func TestNewRequiresLogger(t *testing.T) {
	deps := validDeps(t)
	deps.Logger = nil
	if _, err := New(deps); err == nil || !strings.Contains(err.Error(), "Logger is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewValidatesDependencies(t *testing.T) {
	tests := map[string]struct {
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
		"nil TokenAuthenticator fails": {
			mutate:  func(d *Dependencies) { d.TokenAuthenticator = nil },
			wantErr: true,
		},
		"nil SubjectAccessReviewer fails": {
			mutate:  func(d *Dependencies) { d.SubjectAccessReviewer = nil },
			wantErr: true,
		},
		"nil SecureServingInfo fails": {
			mutate:  func(d *Dependencies) { d.SecureServingInfo = nil },
			wantErr: true,
		},
		"nil Config fails": {
			mutate:  func(d *Dependencies) { d.Config = nil },
			wantErr: true,
		},
		"TokenReview enabled without reviewer fails": {
			mutate: func(d *Dependencies) {
				d.Config = &Config{TokenReview: true, ExternalAddress: "0.0.0.0:1234"}
				d.TokenReviewer = nil
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			deps := validDeps(t)
			tc.mutate(&deps)

			p, err := New(deps)
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

// TestNewCopiesExtraUserHeaders verifies New copies the caller's Config and its
// ExtraUserHeaders map at the construction boundary, so mutating the caller's
// map afterward cannot change proxy behavior.
func TestNewCopiesExtraUserHeaders(t *testing.T) {
	deps := validDeps(t)
	src := map[string][]string{"team": {"platform"}}
	deps.Config = &Config{ExtraUserHeaders: src, ExternalAddress: "0.0.0.0:1234"}

	p, err := New(deps)
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
