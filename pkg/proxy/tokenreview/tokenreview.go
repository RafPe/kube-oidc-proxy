// Copyright Jetstack Ltd. See LICENSE for details.

// Package tokenreview authenticates bearer tokens by submitting TokenReviews to
// the Kubernetes API server.
package tokenreview

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	clientauthv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/pkg/util/token"
)

// defaultTimeout bounds a TokenReview call when no explicit timeout is
// configured. It also backstops zero-valued construction.
const defaultTimeout = 10 * time.Second

type TokenReview struct {
	reviewRequester clientauthv1.TokenReviewInterface
	audiences       []string
	timeout         time.Duration
}

func New(restConfig *rest.Config, audiences []string, timeout time.Duration) (*TokenReview, error) {
	kubeclient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return &TokenReview{
		reviewRequester: kubeclient.AuthenticationV1().TokenReviews(),
		audiences:       audiences,
		timeout:         timeout,
	}, nil
}

// reviewTimeout returns the configured TokenReview budget, defaulting when
// unset so zero-value construction keeps the historical 10s behaviour.
func (t *TokenReview) reviewTimeout() time.Duration {
	if t.timeout > 0 {
		return t.timeout
	}
	return defaultTimeout
}

func (t *TokenReview) Review(req *http.Request) (bool, error) {
	bearer, ok := token.ParseFromRequest(req)
	if !ok {
		return false, errors.New("bearer token not found in request")
	}

	review := t.buildReview(bearer)

	ctx, cancel := context.WithTimeout(req.Context(), t.reviewTimeout())
	defer cancel()

	resp, err := t.reviewRequester.Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}

	if len(resp.Status.Error) > 0 {
		return false, fmt.Errorf("error authenticating using token review: %s",
			resp.Status.Error)
	}

	return resp.Status.Authenticated, nil
}

func (t *TokenReview) buildReview(token string) *authv1.TokenReview {
	return &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: t.audiences,
		},
	}
}
