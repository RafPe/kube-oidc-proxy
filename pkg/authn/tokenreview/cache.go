// Copyright Jetstack Ltd. See LICENSE for details.

package tokenreview

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"log/slog"
	"sync"
	"time"

	utilcache "k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

// tokenCacheSize bounds the number of cached review results. Cache keys derive
// from attacker-supplied bearer tokens, so the cache evicts (LRU) rather than
// let a flood of unique invalid tokens grow it; 8192 entries hold a large
// cluster's live tokens for one TTL in a few megabytes.
const tokenCacheSize = 8192

// newCachedReviewer builds the cache layer with an explicit entry cap and
// clock; both are parameters only so tests can exercise eviction and expiry
// cheaply and deterministically.
//
// Cache keys are an HMAC-SHA256, keyed with a per-instance random key, over
// the length-prefixed token and configured audiences (mirroring the upstream
// cache's keyFunc): tokens are never stored in memory as map keys, keys
// cannot be precomputed or length-extended, and two audience sets can never
// collide; each cache is also private to its reviewer.
func newCachedReviewer(reviewer *liveReviewer, successTTL, failureTTL time.Duration, size int, clk utilcache.Clock) *cachedReviewer {
	randomKey := make([]byte, 32)
	if _, err := rand.Read(randomKey); err != nil {
		panic(err) // rand.Read never fails
	}

	return &cachedReviewer{
		reviewer:   reviewer,
		successTTL: successTTL,
		failureTTL: failureTTL,
		cache:      utilcache.NewLRUExpireCacheWithClock(size, clk),
		hashPool: &sync.Pool{
			New: func() any {
				return hmac.New(sha256.New, randomKey)
			},
		},
	}
}

// cachedReviewer caches the delegate reviewer's results in a
// fixed-capacity LRU store. Entries past their TTL are dropped on lookup, and
// once the store holds tokenCacheSize entries every insertion evicts the
// least recently used one, so a flood of unique (attacker-controlled) tokens
// recycles the same fixed slots instead of growing memory.
type cachedReviewer struct {
	reviewer   *liveReviewer
	successTTL time.Duration
	failureTTL time.Duration

	cache    *utilcache.LRUExpireCache
	hashPool *sync.Pool
}

var _ authenticator.Token = (*cachedReviewer)(nil)

// cacheEntry is the cacheable subset of an AuthenticateToken result. Errors
// are deliberately unrepresentable: only definitive answers are cached.
type cacheEntry struct {
	resp *authenticator.Response
	ok   bool
}

func (c *cachedReviewer) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	key := cacheKey(c.hashPool, token, c.reviewer.audiences)

	if v, hit := c.cache.Get(key); hit {
		entry := v.(cacheEntry)
		c.recordCacheLookup(ctx, metrics.CacheHit, slog.Bool("authenticated", entry.ok))
		return entry.resp, entry.ok, nil
	}
	c.recordCacheLookup(ctx, metrics.CacheMiss)

	resp, ok, err := c.reviewer.AuthenticateToken(ctx, token)
	if err != nil {
		return nil, false, err
	}

	switch {
	case ok && c.successTTL > 0:
		c.cache.Add(key, cacheEntry{resp: resp, ok: true}, c.successTTL)
	case !ok && c.failureTTL > 0:
		c.cache.Add(key, cacheEntry{}, c.failureTTL)
	}

	return resp, ok, nil
}

// recordCacheLookup reports one cache consultation, as a record and as a
// metric.
func (c *cachedReviewer) recordCacheLookup(ctx context.Context, result metrics.CacheResult, attrs ...slog.Attr) {
	attrs = append([]slog.Attr{slog.String("cache_result", string(result))}, attrs...)
	logging.Emit(ctx, c.reviewer.logger, logging.EventCacheTokenReviewLookup, attrs...)
	c.reviewer.metrics.CacheLookup(metrics.ReviewTokenReview, result)
}

// cacheKey hashes the token and audiences into a cache key. Every component
// is length-prefixed so distinct (token, audiences) inputs can never encode
// to the same byte stream (e.g. token "x" with audience "yz" versus token
// "xy" with audience "z").
func cacheKey(hashPool *sync.Pool, token string, audiences []string) string {
	h := hashPool.Get().(hash.Hash)
	defer hashPool.Put(h)
	h.Reset()

	var b [8]byte
	writeLengthPrefixed(h, b[:], token)
	binary.BigEndian.PutUint64(b[:], uint64(len(audiences)))
	h.Write(b[:])
	for _, aud := range audiences {
		writeLengthPrefixed(h, b[:], aud)
	}

	return string(h.Sum(nil))
}

// writeLengthPrefixed writes s preceded by its length. b is a scratch buffer
// of at least 8 bytes.
func writeLengthPrefixed(h hash.Hash, b []byte, s string) {
	binary.BigEndian.PutUint64(b, uint64(len(s)))
	h.Write(b[:8])
	h.Write([]byte(s))
}
