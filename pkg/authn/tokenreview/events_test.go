// Copyright Jetstack Ltd. See LICENSE for details.
package tokenreview

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/utils/clock"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/tokenreview/fake"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

// authenticatedResponse is the API-server reply newCachedWithFake serves:
// every TokenReview comes back authenticated.
func authenticatedResponse(*authv1.TokenReview) (*authv1.TokenReview, error) {
	return authenticatedReview(), nil
}

// newLoggingTokenReview builds a live reviewer that logs through root as the
// tokenreview component, so the records a review emits are observable.
func newLoggingTokenReview(root *slog.Logger, create func(*authv1.TokenReview) (*authv1.TokenReview, error)) *liveReviewer {
	return newLiveReviewer(&fake.Reviewer{CreateFn: create}, Config{}, logging.ForComponent(root, logging.ComponentTokenReview))
}

// newCachedWithFake builds a cached reviewer that logs through root as the
// tokenreview component and answers every review with create. Both TTLs are
// non-zero so the cache is live and hit/miss lookups are observable.
func newCachedWithFake(t *testing.T, root *slog.Logger, create func(*authv1.TokenReview) (*authv1.TokenReview, error)) *cachedReviewer {
	t.Helper()

	return newCachedReviewer(newLoggingTokenReview(root, create), 10*time.Second, 10*time.Second, tokenCacheSize, clock.RealClock{})
}

// TestCachedReviewerEvents pins the records the cache layer emits: one
// lookup per call reporting miss then hit, the cached outcome on the hit, and
// never the bearer token itself.
func TestCachedReviewerEvents(t *testing.T) {
	root, cap := logtest.New(t, 2)
	defer logtest.AssertRegistered(t, cap)
	tr := newCachedWithFake(t, root, authenticatedResponse)
	ctx := logging.WithRequestID(context.Background(), "r1")
	_, _, _ = tr.AuthenticateToken(ctx, "s3cr3t-tok-value")
	_, _, _ = tr.AuthenticateToken(ctx, "s3cr3t-tok-value")
	l := cap.ByEvent(logging.EventCacheTokenReviewLookup)
	if len(l) != 2 || l[0].String("cache_result") != "miss" || l[1].String("cache_result") != "hit" || l[1]["authenticated"] != true {
		t.Fatalf("%v", l)
	}
	if strings.Contains(cap.Raw(), "s3cr3t") {
		t.Fatal("token material logged")
	}
}

// TestLiveTokenReviewCompletedEvent pins the record a live review emits: the
// outcome it reached, how long the API server took, and the correlation id the
// caller's context carries.
func TestLiveTokenReviewCompletedEvent(t *testing.T) {
	tests := map[string]struct {
		review           *authv1.TokenReview
		expAuthenticated bool
		expOK            bool
	}{
		"an authenticated token completes with authenticated=true": {
			review:           authenticatedReview(),
			expAuthenticated: true,
			expOK:            true,
		},
		"a rejected token completes with authenticated=false": {
			review:           unauthenticatedReview(),
			expAuthenticated: false,
			expOK:            false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root, cap := logtest.New(t, 2)
			defer logtest.AssertRegistered(t, cap)
			tr := newLoggingTokenReview(root, func(*authv1.TokenReview) (*authv1.TokenReview, error) {
				return tc.review, nil
			})

			ctx := logging.WithRequestID(context.Background(), "r1")
			_, ok, err := tr.AuthenticateToken(ctx, "s3cr3t-tok-value")
			if err != nil {
				t.Fatalf("AuthenticateToken() error = %v", err)
			}
			if ok != tc.expOK {
				t.Fatalf("ok = %t, want %t", ok, tc.expOK)
			}

			rec := cap.Only(t, logging.EventAuthnTokenReviewCompleted)
			if rec["authenticated"] != tc.expAuthenticated {
				t.Errorf("authenticated = %v, want %t", rec["authenticated"], tc.expAuthenticated)
			}
			if _, present := rec.Int("duration_ms"); !present {
				t.Error("duration_ms missing on a live review")
			}
			if rec.String("request_id") != "r1" {
				t.Errorf("request_id = %q, want r1 from the caller context", rec.String("request_id"))
			}
			if strings.Contains(cap.Raw(), "s3cr3t") {
				t.Error("token material logged")
			}
		})
	}
}

// TestTokenReviewFailureEvent pins the one record a review that never reached
// an answer emits: authn.tokenreview.failed, never a completion record,
// because neither a transport failure nor an API server status error is an
// authentication outcome. A failure is an ERROR, except when the caller's own
// context ended first: a client that hung up cannot drive the ERROR stream.
// The reviewer's own timeout expiring with the caller still waiting means the
// API server did not answer, so it stays an ERROR.
func TestTokenReviewFailureEvent(t *testing.T) {
	tests := map[string]struct {
		timeout   time.Duration
		create    func(ctx context.Context, cancelCaller context.CancelFunc) (*authv1.TokenReview, error)
		expLevel  string
		expReason metrics.Reason
		expErrMsg string
	}{
		"the apiserver call itself failed": {
			create: func(context.Context, context.CancelFunc) (*authv1.TokenReview, error) {
				return nil, errors.New("apiserver unreachable")
			},
			expLevel:  "ERROR",
			expReason: metrics.ReasonAuthenticationDependencyError,
			expErrMsg: "create TokenReview: apiserver unreachable",
		},
		"the apiserver answered with a status error": {
			create: func(context.Context, context.CancelFunc) (*authv1.TokenReview, error) {
				return &authv1.TokenReview{
					Status: authv1.TokenReviewStatus{Error: "token lookup failed"},
				}, nil
			},
			expLevel:  "ERROR",
			expReason: metrics.ReasonAuthenticationDependencyError,
			expErrMsg: "create TokenReview: status error: token lookup failed",
		},
		"the client hung up mid-review": {
			create: func(_ context.Context, cancelCaller context.CancelFunc) (*authv1.TokenReview, error) {
				cancelCaller()
				return nil, context.Canceled
			},
			expLevel:  "DEBUG",
			expReason: metrics.ReasonClientCanceled,
		},
		"the reviewer's own timeout expired": {
			timeout: time.Millisecond,
			create: func(ctx context.Context, _ context.CancelFunc) (*authv1.TokenReview, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
			expLevel:  "ERROR",
			expReason: metrics.ReasonAuthenticationDependencyError,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root, cap := logtest.New(t, 2)
			defer logtest.AssertRegistered(t, cap)

			ctx, cancel := context.WithCancel(testRequestContext())
			defer cancel()
			client := &fake.Reviewer{CreateCtxFn: func(ctx context.Context, _ *authv1.TokenReview) (*authv1.TokenReview, error) {
				return tc.create(ctx, cancel)
			}}
			tr := newLiveReviewer(client, Config{Timeout: tc.timeout}, logging.ForComponent(root, logging.ComponentTokenReview))

			_, ok, err := tr.AuthenticateToken(ctx, "s3cr3t-tok-value")
			if !errors.Is(err, ErrCreateTokenReview) || ok {
				t.Fatalf("want a failed review wrapping ErrCreateTokenReview, got ok=%t err=%v", ok, err)
			}

			rec := cap.Only(t, logging.EventAuthnTokenReviewFailed)
			if got := rec.String("level"); got != tc.expLevel {
				t.Errorf("level = %q, want %q", got, tc.expLevel)
			}
			if got := rec.String("reason"); got != string(tc.expReason) {
				t.Errorf("reason = %q, want %q", got, tc.expReason)
			}
			if got := rec.String("error_message"); got != err.Error() {
				t.Errorf("error_message = %q, want the returned error %q", got, err.Error())
			}
			if tc.expErrMsg != "" && err.Error() != tc.expErrMsg {
				t.Errorf("error = %q, want %q", err.Error(), tc.expErrMsg)
			}
			if got := rec.String("request_id"); got != "test-request" {
				t.Errorf("request_id = %q, want test-request from the caller context", got)
			}
			if got := cap.ByEvent(logging.EventAuthnTokenReviewCompleted); len(got) != 0 {
				t.Errorf("a failed review must not emit a completion record, got %v", got)
			}
			if strings.Contains(cap.Raw(), "s3cr3t") {
				t.Error("token material logged")
			}
		})
	}
}

// TestCachedReviewerHitCarriesNoDuration pins the timing boundary: only a
// live review reports duration_ms, so a cache hit can never be mistaken for a
// very fast API server.
func TestCachedReviewerHitCarriesNoDuration(t *testing.T) {
	root, cap := logtest.New(t, 2)
	defer logtest.AssertRegistered(t, cap)
	tr := newCachedWithFake(t, root, authenticatedResponse)
	ctx := logging.WithRequestID(context.Background(), "r1")

	for i := range 2 {
		if _, ok, err := tr.AuthenticateToken(ctx, "s3cr3t-tok-value"); err != nil || !ok {
			t.Fatalf("call %d: unexpected result, ok=%t err=%v", i, ok, err)
		}
	}

	lookups := cap.ByEvent(logging.EventCacheTokenReviewLookup)
	if len(lookups) != 2 {
		t.Fatalf("want 2 cache lookups, got %d: %v", len(lookups), lookups)
	}
	if _, present := lookups[1].Int("duration_ms"); present {
		t.Errorf("a cache hit must not report duration_ms, got %v", lookups[1])
	}
	if lookups[1].String("request_id") != "r1" {
		t.Errorf("request_id = %q, want r1 from the caller context", lookups[1].String("request_id"))
	}

	// Only the first call reached the API server, so only it is timed.
	live := cap.Only(t, logging.EventAuthnTokenReviewCompleted)
	if _, present := live.Int("duration_ms"); !present {
		t.Error("duration_ms missing on the live review")
	}
}
