// Copyright Jetstack Ltd. See LICENSE for details.

// Package tokenreview authenticates bearer tokens by submitting TokenReviews to
// the Kubernetes API server.
package tokenreview

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/authentication/authenticator"
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

// NewCached wraps reviewer in a TokenReview result cache. Successful reviews
// are cached for successTTL and unauthenticated results for failureTTL.
// Errors (API server unreachable, timeout, status.Error) are never cached, so
// a transient failure is retried on the next request and the path stays
// fail-closed. When both TTLs are zero (or negative) the reviewer is returned
// unwrapped and behaves exactly as before caching existed.
//
// A cache miss runs the TokenReview on the caller's own context, so caching
// preserves the uncached request contract exactly: the configured review
// timeout applies in full (including values above 30s) and cancelling the
// inbound request cancels its in-flight review. The deliberate trade-off is
// that concurrent misses for one token are not collapsed into a single
// review — each runs its own, exactly as every request did before caching
// existed — so the cache only ever subtracts load. (The upstream
// kube-apiserver token cache deduplicates via singleflight instead, but pays
// for it by running lookups on a detached context with a hardcoded 30s cap,
// which would silently truncate longer configured timeouts and detach client
// cancellation.)
//
// Security: a cached success outlives token revocation for up to successTTL,
// so a token deleted or invalidated at the API server may still pass through
// this proxy until its cache entry expires. Keep successTTL small; the
// kube-apiserver's own precedent is 10s.
//
// Cache keys are an HMAC-SHA256, keyed with a per-instance random key, over
// the length-prefixed token and configured audiences (mirroring the upstream
// cache's keyFunc): tokens are never stored in memory as map keys, keys
// cannot be precomputed or length-extended, and two audience sets can never
// collide — each NewCached call also owns a private cache.
func NewCached(reviewer *TokenReview, successTTL, failureTTL time.Duration) authenticator.Token {
	if successTTL <= 0 && failureTTL <= 0 {
		return reviewer
	}

	randomKey := make([]byte, 32)
	if _, err := rand.Read(randomKey); err != nil {
		panic(err) // rand.Read never fails
	}

	return &cachedTokenReview{
		reviewer:   reviewer,
		successTTL: successTTL,
		failureTTL: failureTTL,
		cache:      utilcache.NewExpiring(),
		hashPool: &sync.Pool{
			New: func() any {
				return hmac.New(sha256.New, randomKey)
			},
		},
	}
}

// cachedTokenReview caches the delegate reviewer's results, bounded by the
// success/failure TTLs. Entries past their TTL are dropped by the Expiring
// store on lookup and garbage-collected on insertion, so memory is bounded by
// the tokens seen within one TTL window.
type cachedTokenReview struct {
	reviewer   *TokenReview
	successTTL time.Duration
	failureTTL time.Duration

	cache    *utilcache.Expiring
	hashPool *sync.Pool
}

var _ authenticator.Token = (*cachedTokenReview)(nil)

// cachedReview is the cacheable subset of an AuthenticateToken result. Errors
// are deliberately unrepresentable: only definitive answers are cached.
type cachedReview struct {
	resp *authenticator.Response
	ok   bool
}

func (c *cachedTokenReview) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	key := cacheKey(c.hashPool, token, c.reviewer.audiences)

	if v, hit := c.cache.Get(key); hit {
		record := v.(cachedReview)
		return record.resp, record.ok, nil
	}

	resp, ok, err := c.reviewer.AuthenticateToken(ctx, token)
	if err != nil {
		return nil, false, err
	}

	switch {
	case ok && c.successTTL > 0:
		c.cache.Set(key, cachedReview{resp: resp, ok: true}, c.successTTL)
	case !ok && c.failureTTL > 0:
		c.cache.Set(key, cachedReview{}, c.failureTTL)
	}

	return resp, ok, nil
}

// cacheKey hashes the token and audiences into a cache key. Every component
// is length-prefixed so distinct (token, audiences) inputs can never encode
// to the same byte stream (e.g. token "x" with audience "yz" versus token
// "xy" with audience "z").
func cacheKey(hashPool *sync.Pool, token string, audiences []string) string {
	h := hashPool.Get().(hash.Hash)
	defer hashPool.Put(h)
	h.Reset()

	var b [4]byte
	writeLengthPrefixed(h, b[:], token)
	binary.BigEndian.PutUint32(b[:], uint32(len(audiences)))
	h.Write(b[:])
	for _, aud := range audiences {
		writeLengthPrefixed(h, b[:], aud)
	}

	return string(h.Sum(nil))
}

// writeLengthPrefixed writes s preceded by its length. b is a scratch buffer
// of at least 4 bytes.
func writeLengthPrefixed(h hash.Hash, b []byte, s string) {
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	h.Write(b[:4])
	h.Write([]byte(s))
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
