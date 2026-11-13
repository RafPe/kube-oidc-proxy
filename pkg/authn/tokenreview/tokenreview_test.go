// Copyright Jetstack Ltd. See LICENSE for details.
package tokenreview

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/tokenreview/fake"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// discardLogger stands in for the component logger New requires, for the
// tests that assert on behaviour rather than on records.
var discardLogger = slog.New(slog.DiscardHandler)

// testRequestContext returns a context carrying a request id, exactly as the
// proxy's request filter installs one in production. Every record this package
// emits requires request_id, so a bare context trips the logcheck build.
func testRequestContext() context.Context {
	return logging.WithRequestID(context.Background(), "test-request")
}

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
			tReviewer := newReviewer(fake.New().WithCreate(test.reviewResp, test.errResp), Config{}, discardLogger)

			resp, ok, err := tReviewer.AuthenticateToken(testRequestContext(), "test-token")

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

// TestNewReviewerSettlesTheTimeout pins the timeout plumbing: the configured
// value is used, and zero or negative falls back to the default at
// construction, so the reviewer needs no zero-value accommodation.
func TestNewReviewerSettlesTheTimeout(t *testing.T) {
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
			if got := newReviewer(fake.New(), Config{Timeout: test.timeout}, discardLogger).timeout; got != test.exp {
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
