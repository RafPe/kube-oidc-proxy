// Copyright Jetstack Ltd. See LICENSE for details.
package tokenreview

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/tokenreview/fake"
)

type testT struct {
	reviewResp *authv1.TokenReview
	errResp    error

	expAuth bool
	expErr  error
}

func TestReview(t *testing.T) {

	tests := map[string]testT{
		"if a create fails then this error is returned": {
			reviewResp: nil,
			errResp:    errors.New("create error response"),
			expAuth:    false,
			expErr:     errors.New("create error response"),
		},

		"if an error exists in the status of the response pass error back": {
			reviewResp: &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Error: "status error",
				},
			},
			errResp: nil,
			expAuth: false,
			expErr:  errors.New("error authenticating using token review: status error"),
		},

		"if the response returns unauthenticated, return false": {
			reviewResp: &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: false,
				},
			},
			errResp: nil,
			expAuth: false,
			expErr:  nil,
		},

		"if the response returns authenticated, return true": {
			reviewResp: &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
				},
			},
			errResp: nil,
			expAuth: true,
			expErr:  nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			runTest(t, test)
		})
	}
}

func runTest(t *testing.T, test testT) {
	tReviewer := &TokenReview{
		audiences:       nil,
		reviewRequester: fake.New().WithCreate(test.reviewResp, test.errResp),
	}

	authed, err := tReviewer.Review(
		&http.Request{
			Header: map[string][]string{
				"Authorization": {"bearer test-token"},
			},
		},
	)

	if !reflect.DeepEqual(test.expErr, err) {
		t.Errorf("got unexpected error, exp=%v got=%v",
			test.expErr, err)
	}

	if test.expAuth != authed {
		t.Errorf("got unexpected authed, exp=%t got=%t",
			test.expAuth, authed)
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
