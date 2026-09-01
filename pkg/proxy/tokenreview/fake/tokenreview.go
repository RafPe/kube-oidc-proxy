// Copyright Jetstack Ltd. See LICENSE for details.

// Package fake provides a stub TokenReviewInterface for use in tests.
package fake

import (
	"context"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
)

var _ clientauthv1.TokenReviewInterface = &FakeReviewer{}

type FakeReviewer struct {
	CreateFn func(*authv1.TokenReview) (*authv1.TokenReview, error)

	// CreateCtxFn, when set, takes precedence over CreateFn and additionally
	// receives the request context, so tests can observe the deadline and
	// cancellation the reviewer applies.
	CreateCtxFn func(context.Context, *authv1.TokenReview) (*authv1.TokenReview, error)
}

func New() *FakeReviewer {
	return &FakeReviewer{
		CreateFn: func(*authv1.TokenReview) (*authv1.TokenReview, error) {
			return nil, nil
		},
	}
}

func (f *FakeReviewer) Create(ctx context.Context, req *authv1.TokenReview, co metav1.CreateOptions) (*authv1.TokenReview, error) {
	if f.CreateCtxFn != nil {
		return f.CreateCtxFn(ctx, req)
	}
	return f.CreateFn(req)
}

func (f *FakeReviewer) CreateContext(ctx context.Context, req *authv1.TokenReview) (*authv1.TokenReview, error) {
	return f.CreateFn(req)
}

func (f *FakeReviewer) WithCreate(req *authv1.TokenReview, err error) *FakeReviewer {
	f.CreateFn = func(*authv1.TokenReview) (*authv1.TokenReview, error) {
		return req, err
	}

	return f
}
