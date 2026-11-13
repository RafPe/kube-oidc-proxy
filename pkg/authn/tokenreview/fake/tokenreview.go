// Copyright Jetstack Ltd. See LICENSE for details.

// Package fake provides a stub TokenReviewInterface for use in tests.
package fake

import (
	"context"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
)

var _ clientauthv1.TokenReviewInterface = &Reviewer{}

// Reviewer is a programmable TokenReviewInterface: each test decides what
// Create returns, either from the review alone (CreateFn) or from the review and
// its context (CreateCtxFn).
type Reviewer struct {
	CreateFn func(*authv1.TokenReview) (*authv1.TokenReview, error)

	// CreateCtxFn, when set, takes precedence over CreateFn and additionally
	// receives the request context, so tests can observe the deadline and
	// cancellation the reviewer applies.
	CreateCtxFn func(context.Context, *authv1.TokenReview) (*authv1.TokenReview, error)
}

// New returns a Reviewer whose Create returns no review and no error until a
// test programs it.
func New() *Reviewer {
	return &Reviewer{
		CreateFn: func(*authv1.TokenReview) (*authv1.TokenReview, error) {
			return nil, nil
		},
	}
}

// Create implements TokenReviewInterface.
func (f *Reviewer) Create(ctx context.Context, req *authv1.TokenReview, co metav1.CreateOptions) (*authv1.TokenReview, error) {
	if f.CreateCtxFn != nil {
		return f.CreateCtxFn(ctx, req)
	}
	return f.CreateFn(req)
}

// WithCreate makes every Create return req and err, and returns f for chaining.
func (f *Reviewer) WithCreate(req *authv1.TokenReview, err error) *Reviewer {
	f.CreateFn = func(*authv1.TokenReview) (*authv1.TokenReview, error) {
		return req, err
	}

	return f
}
