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
)

// authenticatedResponse is the API-server reply newCachedWithFake serves:
// every TokenReview comes back authenticated.
func authenticatedResponse(*authv1.TokenReview) (*authv1.TokenReview, error) {
	return authenticatedReview(), nil
}

// newLoggingTokenReview builds a live reviewer that logs through root as the
// tokenreview component, so the records a review emits are observable.
func newLoggingTokenReview(root *slog.Logger, create func(*authv1.TokenReview) (*authv1.TokenReview, error)) *liveReviewer {
	return newReviewer(&fake.FakeReviewer{CreateFn: create}, Config{}, logging.ForComponent(root, logging.ComponentTokenReview))
}

// newCachedWithFake builds a cached reviewer that logs through root as the
// tokenreview component and answers every review with create. Both TTLs are
// non-zero so the cache is live and hit/miss lookups are observable.
func newCachedWithFake(t *testing.T, root *slog.Logger, create func(*authv1.TokenReview) (*authv1.TokenReview, error)) *cachedTokenReview {
	t.Helper()

	return newCachedTokenReview(newLoggingTokenReview(root, create), 10*time.Second, 10*time.Second, tokenCacheSize, clock.RealClock{})
}

// TestCachedTokenReviewEvents pins the records the cache layer emits: one
// lookup per call reporting miss then hit, the cached outcome on the hit, and
// never the bearer token itself.
func TestCachedTokenReviewEvents(t *testing.T) {
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

// TestTokenReviewFailureEmitsNoCompletedEvent pins that a review which never
// reached an answer emits no completion record: neither a transport failure nor
// an API server status error is an authentication outcome. The ERROR record for
// those is authn.tokenreview.failed, emitted by the caller.
func TestTokenReviewFailureEmitsNoCompletedEvent(t *testing.T) {
	tests := map[string]func(*authv1.TokenReview) (*authv1.TokenReview, error){
		"the apiserver call itself failed": func(*authv1.TokenReview) (*authv1.TokenReview, error) {
			return nil, errors.New("apiserver unreachable")
		},
		"the apiserver answered with a status error": func(*authv1.TokenReview) (*authv1.TokenReview, error) {
			return &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{Error: "token lookup failed"},
			}, nil
		},
	}

	for name, create := range tests {
		t.Run(name, func(t *testing.T) {
			root, cap := logtest.New(t, 2)
			defer logtest.AssertRegistered(t, cap)
			tr := newLoggingTokenReview(root, create)

			if _, ok, err := tr.AuthenticateToken(testRequestContext(), "s3cr3t-tok-value"); err == nil || ok {
				t.Fatalf("want a failed review, got ok=%t err=%v", ok, err)
			}

			if got := cap.ByEvent(logging.EventAuthnTokenReviewCompleted); len(got) != 0 {
				t.Errorf("a failed review must not emit a completion record, got %v", got)
			}
		})
	}
}

// TestCachedTokenReviewHitCarriesNoDuration pins the timing boundary: only a
// live review reports duration_ms, so a cache hit can never be mistaken for a
// very fast API server.
func TestCachedTokenReviewHitCarriesNoDuration(t *testing.T) {
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
