// Copyright Jetstack Ltd. See LICENSE for details.
package tokenreview

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	clientauthv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/tokenreview/fake"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// discardLogger stands in for the component logger New requires, for the
// tests that assert on behaviour rather than on records.
var discardLogger = slog.New(slog.DiscardHandler)

// newLiveReviewer returns the uncached reviewer New builds for cfg, with the
// cache switched off.
func newLiveReviewer(client clientauthv1.TokenReviewInterface, cfg Config, logger *slog.Logger) *liveReviewer {
	cfg.SuccessCacheTTL, cfg.FailureCacheTTL = 0, 0
	return New(client, cfg, logger).(*liveReviewer)
}

// testRequestContext returns a context carrying a request id, exactly as the
// proxy's request filter installs one in production. Every record this package
// emits requires request_id, so a bare context trips the logcheck build.
func testRequestContext() context.Context {
	return logging.WithRequestID(context.Background(), "test-request")
}

// TestNewSettlesTheTimeout pins the timeout plumbing: the configured
// value is used, and zero or negative falls back to the default at
// construction, so the reviewer needs no zero-value accommodation.
func TestNewSettlesTheTimeout(t *testing.T) {
	tests := map[string]struct {
		timeout time.Duration
		exp     time.Duration
	}{
		"configured timeout is used":     {timeout: 3 * time.Second, exp: 3 * time.Second},
		"zero falls back to default":     {timeout: 0, exp: DefaultTimeout},
		"negative falls back to default": {timeout: -time.Second, exp: DefaultTimeout},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := newLiveReviewer(fake.New(), Config{Timeout: test.timeout}, discardLogger).timeout; got != test.exp {
				t.Errorf("unexpected review timeout, exp=%s got=%s", test.exp, got)
			}
		})
	}
}

// TestNewPanicsOnNilLogger pins that a missing logger is a wiring mistake that
// fails at construction, naming the package, rather than on the first
// passthrough request.
func TestNewPanicsOnNilLogger(t *testing.T) {
	defer func() {
		if got := recover(); got != "tokenreview: nil logger" {
			t.Fatalf("New(nil logger) panic = %v, want %q", got, "tokenreview: nil logger")
		}
	}()
	New(fake.New(), Config{}, nil)
}

// TestFailedReviewKeepsTheContextErrorMatchable pins that wrapping a failure
// in ErrCreateTokenReview does not hide its cause: a caller deciding whether
// the client hung up still finds context.Canceled through the cache layer.
func TestFailedReviewKeepsTheContextErrorMatchable(t *testing.T) {
	client := &fake.Reviewer{
		CreateCtxFn: func(ctx context.Context, _ *authv1.TokenReview) (*authv1.TokenReview, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	tr := New(client, Config{SuccessCacheTTL: DefaultSuccessCacheTTL, FailureCacheTTL: DefaultFailureCacheTTL}, discardLogger)

	ctx, cancel := context.WithCancel(testRequestContext())
	cancel()
	_, ok, err := tr.AuthenticateToken(ctx, "test-token")
	if ok {
		t.Fatal("a canceled review must not authenticate")
	}
	if !errors.Is(err, ErrCreateTokenReview) || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want both ErrCreateTokenReview and context.Canceled", err)
	}
}
