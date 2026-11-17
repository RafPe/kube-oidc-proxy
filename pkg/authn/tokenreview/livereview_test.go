// Copyright Jetstack Ltd. See LICENSE for details.
package tokenreview

import (
	"errors"
	"reflect"
	"testing"

	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/tokenreview/fake"
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
			expErr:     "create TokenReview: create error response",
		},

		"if an error exists in the status of the response pass error back": {
			reviewResp: &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Error: "status error",
				},
			},
			expOK:  false,
			expErr: "create TokenReview: status error: status error",
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
			tReviewer := newLiveReviewer(fake.New().WithCreate(test.reviewResp, test.errResp), Config{}, discardLogger)

			resp, ok, err := tReviewer.AuthenticateToken(testRequestContext(), "test-token")

			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if test.expErr != gotErr {
				t.Errorf("got unexpected error, exp=%q got=%q", test.expErr, gotErr)
			}
			// Every failure is a dependency failure the caller can classify.
			if err != nil && !errors.Is(err, ErrCreateTokenReview) {
				t.Errorf("error = %v, want errors.Is(ErrCreateTokenReview)", err)
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
