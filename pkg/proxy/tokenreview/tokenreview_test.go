// Copyright Jetstack Ltd. See LICENSE for details.
package tokenreview

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/tokenreview/fake"
)

func TestAuthenticateToken(t *testing.T) {
	tests := map[string]struct {
		reviewResp *authv1.TokenReview
		errResp    error

		expOK   bool
		expErr  string
		expUser user.Info
	}{
		"if a create fails then this error is returned": {
			reviewResp: nil,
			errResp:    errors.New("create error response"),
			expOK:      false,
			expErr:     "create error response",
		},

		"if an error exists in the status of the response pass error back": {
			reviewResp: &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Error: "status error",
				},
			},
			expOK:  false,
			expErr: "error authenticating using token review: status error",
		},

		"if the response returns unauthenticated, return not ok with no error": {
			reviewResp: &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: false,
				},
			},
			expOK: false,
		},

		"if the response returns authenticated, return ok with the reviewed identity": {
			reviewResp: &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					User: authv1.UserInfo{
						Username: "user-a",
						UID:      "uid-1",
						Groups:   []string{"group-a", "group-b"},
						Extra:    map[string]authv1.ExtraValue{"key": {"value"}},
					},
				},
			},
			expOK: true,
			expUser: &user.DefaultInfo{
				Name:   "user-a",
				UID:    "uid-1",
				Groups: []string{"group-a", "group-b"},
				Extra:  map[string][]string{"key": {"value"}},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tReviewer := &TokenReview{
				reviewRequester: fake.New().WithCreate(test.reviewResp, test.errResp),
			}

			resp, ok, err := tReviewer.AuthenticateToken(context.Background(), "test-token")

			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if test.expErr != gotErr {
				t.Errorf("got unexpected error, exp=%q got=%q", test.expErr, gotErr)
			}

			if test.expOK != ok {
				t.Errorf("got unexpected ok, exp=%t got=%t", test.expOK, ok)
			}

			if test.expUser != nil {
				if resp == nil {
					t.Fatal("expected a response for an authenticated token, got nil")
				}
				if !reflect.DeepEqual(test.expUser, resp.User) {
					t.Errorf("got unexpected user, exp=%#v got=%#v", test.expUser, resp.User)
				}
			} else if resp != nil {
				t.Errorf("expected no response, got %#v", resp)
			}
		})
	}
}

// TestReviewTimeout pins the timeout plumbing: New stores what it is given,
// and the zero value falls back to the default so struct-literal construction
// (as the tests above do) keeps the old behaviour.
func TestReviewTimeout(t *testing.T) {
	tests := map[string]struct {
		timeout time.Duration
		exp     time.Duration
	}{
		"configured timeout is used":     {timeout: 3 * time.Second, exp: 3 * time.Second},
		"zero falls back to default":     {timeout: 0, exp: defaultTimeout},
		"negative falls back to default": {timeout: -time.Second, exp: defaultTimeout},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr := &TokenReview{timeout: test.timeout}
			if got := tr.reviewTimeout(); got != test.exp {
				t.Errorf("unexpected review timeout, exp=%s got=%s", test.exp, got)
			}
		})
	}
}

func authenticatedReview() *authv1.TokenReview {
	return &authv1.TokenReview{
		Status: authv1.TokenReviewStatus{
			Authenticated: true,
			User:          authv1.UserInfo{Username: "user-a"},
		},
	}
}

func unauthenticatedReview() *authv1.TokenReview {
	return &authv1.TokenReview{
		Status: authv1.TokenReviewStatus{Authenticated: false},
	}
}

// TestNewCached exercises the cached reviewer end to end against a counting
// fake: which results are served from cache, which always go back to the API
// server, and how the TTLs bound reuse.
func TestNewCached(t *testing.T) {
	type step struct {
		token       string
		sleepBefore time.Duration
		expOK       bool
		expErr      bool
	}

	tests := map[string]struct {
		successTTL time.Duration
		failureTTL time.Duration

		// create serves the fake API server. call is 1-based.
		create func(call int64, review *authv1.TokenReview) (*authv1.TokenReview, error)

		steps    []step
		expCalls int64
	}{
		"a cache hit avoids a second apiserver call": {
			successTTL: 10 * time.Second,
			failureTTL: 10 * time.Second,
			create: func(int64, *authv1.TokenReview) (*authv1.TokenReview, error) {
				return authenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: true},
				{token: "token-a", expOK: true},
			},
			expCalls: 1,
		},

		"distinct tokens get distinct cache entries": {
			successTTL: 10 * time.Second,
			failureTTL: 10 * time.Second,
			create: func(_ int64, review *authv1.TokenReview) (*authv1.TokenReview, error) {
				if review.Spec.Token == "token-a" {
					return authenticatedReview(), nil
				}
				return unauthenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: true},
				{token: "token-b", expOK: false},
				{token: "token-a", expOK: true},
				{token: "token-b", expOK: false},
			},
			expCalls: 2,
		},

		"error results are not cached and are retried on the next request": {
			successTTL: 10 * time.Second,
			failureTTL: 10 * time.Second,
			create: func(call int64, _ *authv1.TokenReview) (*authv1.TokenReview, error) {
				if call == 1 {
					return nil, errors.New("apiserver unreachable")
				}
				return authenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: false, expErr: true},
				{token: "token-a", expOK: true},
			},
			expCalls: 2,
		},

		"unauthenticated results are cached for the failure TTL": {
			successTTL: 10 * time.Second,
			failureTTL: 10 * time.Second,
			create: func(int64, *authv1.TokenReview) (*authv1.TokenReview, error) {
				return unauthenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: false},
				{token: "token-a", expOK: false},
			},
			expCalls: 1,
		},

		"success TTL expiry forces a fresh review": {
			successTTL: 20 * time.Millisecond,
			failureTTL: 10 * time.Second,
			create: func(int64, *authv1.TokenReview) (*authv1.TokenReview, error) {
				return authenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: true},
				{token: "token-a", sleepBefore: 100 * time.Millisecond, expOK: true},
			},
			expCalls: 2,
		},

		"zero failure TTL leaves unauthenticated results uncached": {
			successTTL: 10 * time.Second,
			failureTTL: 0,
			create: func(int64, *authv1.TokenReview) (*authv1.TokenReview, error) {
				return unauthenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: false},
				{token: "token-a", expOK: false},
			},
			expCalls: 2,
		},

		"zero TTLs bypass the cache entirely": {
			successTTL: 0,
			failureTTL: 0,
			create: func(int64, *authv1.TokenReview) (*authv1.TokenReview, error) {
				return authenticatedReview(), nil
			},
			steps: []step{
				{token: "token-a", expOK: true},
				{token: "token-a", expOK: true},
			},
			expCalls: 2,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			reviewer := &TokenReview{
				reviewRequester: &fake.FakeReviewer{
					CreateFn: func(review *authv1.TokenReview) (*authv1.TokenReview, error) {
						return test.create(calls.Add(1), review)
					},
				},
			}

			cached := NewCached(reviewer, test.successTTL, test.failureTTL)

			for i, s := range test.steps {
				if s.sleepBefore > 0 {
					time.Sleep(s.sleepBefore)
				}

				_, ok, err := cached.AuthenticateToken(context.Background(), s.token)
				if s.expErr != (err != nil) {
					t.Fatalf("step %d: unexpected error state, expErr=%t got=%v", i, s.expErr, err)
				}
				if s.expOK != ok {
					t.Fatalf("step %d: unexpected ok, exp=%t got=%t", i, s.expOK, ok)
				}
			}

			if got := calls.Load(); got != test.expCalls {
				t.Errorf("unexpected number of apiserver calls, exp=%d got=%d", test.expCalls, got)
			}
		})
	}
}

// TestNewCachedZeroTTLsReturnsBareReviewer pins that disabling both TTLs keeps
// the exact pre-cache behaviour: no cache layer, no singleflight, no detached
// context.
func TestNewCachedZeroTTLsReturnsBareReviewer(t *testing.T) {
	reviewer := &TokenReview{reviewRequester: fake.New()}
	if got := NewCached(reviewer, 0, 0); got != reviewer {
		t.Errorf("expected the bare reviewer back for zero TTLs, got %T", got)
	}
}

// TestCachedReviewSendsConfiguredAudiences verifies the audiences configured
// on the reviewer still reach the API server in the TokenReview spec when the
// cache wrapper is in place.
func TestCachedReviewSendsConfiguredAudiences(t *testing.T) {
	audiences := []string{"aud-1", "aud-2"}

	var gotAudiences []string
	reviewer := &TokenReview{
		audiences: audiences,
		reviewRequester: &fake.FakeReviewer{
			CreateFn: func(review *authv1.TokenReview) (*authv1.TokenReview, error) {
				gotAudiences = review.Spec.Audiences
				return authenticatedReview(), nil
			},
		},
	}

	cached := NewCached(reviewer, 10*time.Second, 10*time.Second)

	if _, ok, err := cached.AuthenticateToken(context.Background(), "token-a"); err != nil || !ok {
		t.Fatalf("unexpected review result, ok=%t err=%v", ok, err)
	}

	if !reflect.DeepEqual(audiences, gotAudiences) {
		t.Errorf("unexpected audiences on the review, exp=%v got=%v", audiences, gotAudiences)
	}
}
