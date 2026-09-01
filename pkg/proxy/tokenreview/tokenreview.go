// Copyright Jetstack Ltd. See LICENSE for details.

// Package tokenreview authenticates bearer tokens by submitting TokenReviews to
// the Kubernetes API server.
package tokenreview

import (
	"context"
	"fmt"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/token/cache"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	clientauthv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
)

// defaultTimeout bounds a TokenReview call when no explicit timeout is
// configured. It also backstops zero-valued construction.
const defaultTimeout = 10 * time.Second

// TokenReview submits a live TokenReview to the API server for every call. It
// implements authenticator.Token; wrap it with NewCached to avoid repeating
// the round trip for tokens seen recently.
type TokenReview struct {
	reviewRequester clientauthv1.TokenReviewInterface
	audiences       []string
	timeout         time.Duration
}

var _ authenticator.Token = (*TokenReview)(nil)

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

// NewCached wraps reviewer in the upstream token result cache
// (k8s.io/apiserver/pkg/authentication/token/cache), the same cache the
// kube-apiserver's delegating authenticator uses. Successful reviews are
// cached for successTTL and unauthenticated results for failureTTL, and
// concurrent calls for one token collapse into a single TokenReview via
// singleflight. Errors (API server unreachable, timeout, status.Error) are
// never cached, so a transient failure is retried on the next request and the
// path stays fail-closed. When both TTLs are zero (or negative) the reviewer
// is returned unwrapped and behaves exactly as before caching existed.
//
// Security: a cached success outlives token revocation for up to successTTL,
// so a token deleted or invalidated at the API server may still pass through
// this proxy until its cache entry expires. Keep successTTL small; the
// kube-apiserver's own precedent is 10s.
//
// Cache keys are an HMAC of the token plus any audiences carried in the
// context (see keyFunc in the upstream package). The reviewer's configured
// audiences are fixed at construction and each NewCached call owns a private
// cache with a per-instance random HMAC key, so two audience sets can never
// collide; the audiences are still injected into the context on every call so
// the key covers them explicitly.
//
// Note: when caching is enabled the shared lookup runs on a detached context
// capped at 30s by the upstream cache, so a configured review timeout above
// 30s is effectively truncated, and client disconnects no longer cancel an
// in-flight review (waiters return immediately; the shared lookup completes
// and populates the cache).
func NewCached(reviewer *TokenReview, successTTL, failureTTL time.Duration) authenticator.Token {
	if successTTL <= 0 && failureTTL <= 0 {
		return reviewer
	}

	return &audienceKeyedCache{
		delegate:  cache.New(reviewer, false, successTTL, failureTTL),
		audiences: authenticator.Audiences(reviewer.audiences),
	}
}

// audienceKeyedCache injects the reviewer's configured audiences into the
// context before delegating to the cached authenticator, so the cache key is
// derived from token+audiences rather than the token alone.
type audienceKeyedCache struct {
	delegate  authenticator.Token
	audiences authenticator.Audiences
}

func (a *audienceKeyedCache) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	if len(a.audiences) > 0 {
		ctx = authenticator.WithAudiences(ctx, a.audiences)
	}
	return a.delegate.AuthenticateToken(ctx, token)
}

// reviewTimeout returns the configured TokenReview budget, defaulting when
// unset so zero-value construction keeps the historical 10s behaviour.
func (t *TokenReview) reviewTimeout() time.Duration {
	if t.timeout > 0 {
		return t.timeout
	}
	return defaultTimeout
}

// AuthenticateToken implements authenticator.Token by submitting a
// TokenReview for the bearer token. It returns ok=false with a nil error when
// the API server answers but does not authenticate the token, and a non-nil
// error when the review itself failed; callers must treat both as
// unauthenticated (fail closed).
func (t *TokenReview) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, t.reviewTimeout())
	defer cancel()

	resp, err := t.reviewRequester.Create(ctx, t.buildReview(token), metav1.CreateOptions{})
	if err != nil {
		return nil, false, err
	}

	if len(resp.Status.Error) > 0 {
		return nil, false, fmt.Errorf("error authenticating using token review: %s",
			resp.Status.Error)
	}

	if !resp.Status.Authenticated {
		return nil, false, nil
	}

	return &authenticator.Response{
		Audiences: authenticator.Audiences(resp.Status.Audiences),
		User:      userInfoFrom(resp.Status.User),
	}, true, nil
}

// userInfoFrom converts the TokenReview status identity into the
// authenticator's user.Info shape.
func userInfoFrom(ui authv1.UserInfo) user.Info {
	info := &user.DefaultInfo{
		Name:   ui.Username,
		UID:    ui.UID,
		Groups: ui.Groups,
	}
	if len(ui.Extra) > 0 {
		info.Extra = make(map[string][]string, len(ui.Extra))
		for k, v := range ui.Extra {
			info.Extra[k] = v
		}
	}
	return info
}

func (t *TokenReview) buildReview(token string) *authv1.TokenReview {
	return &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: t.audiences,
		},
	}
}
