// Copyright Jetstack Ltd. See LICENSE for details.

package subjectaccessreview

import (
	"encoding/json"
	"time"

	v1 "k8s.io/api/authorization/v1"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
)

const (
	// DefaultAllowCacheTTL is the default duration an allowed impersonation
	// decision is served from the cache. It matches the delegating-authorization
	// default in k8s.io/apiserver ("very low for responsiveness, but high enough
	// to handle storms"). The tradeoff is revocation lag: an RBAC revoke can
	// take up to this long to be enforced for a requester whose allow decision
	// is cached.
	DefaultAllowCacheTTL = 10 * time.Second

	// DefaultDenyCacheTTL is the default duration a denied impersonation
	// decision is served from the cache. A newly granted RBAC permission can
	// take up to this long to be honoured.
	DefaultDenyCacheTTL = 10 * time.Second

	// decisionCacheSize bounds the number of cached decisions. Cache keys embed
	// attacker-influenced impersonation header values, so the cache must evict
	// (LRU) rather than grow without bound. The size mirrors the response cache
	// of the upstream webhook authorizer.
	decisionCacheSize = 8192

	// maxCacheKeySize bounds the serialized review spec eligible for caching.
	// Oversized entries (e.g. absurdly long impersonation header values) are
	// still authorized live, just never cached, so a client cannot fill the
	// cache with huge keys. Mirrors maxControlledAttrCacheSize in the upstream
	// webhook authorizer.
	maxCacheKeySize = 10000
)

// decisionCache caches definitive SubjectAccessReview decisions (allow/deny)
// with split TTLs, mirroring the response cache of the upstream webhook
// authorizer (k8s.io/apiserver/plugin/pkg/authorizer/webhook). Only decisions
// are cached; errors never are. A nil *decisionCache is valid and disables
// caching entirely — all methods are nil-safe.
type decisionCache struct {
	lru *utilcache.LRUExpireCache

	// allowTTL is how long an allowed decision is served from the cache.
	// Zero or negative disables caching of allowed decisions.
	allowTTL time.Duration

	// denyTTL is how long a denied decision is served from the cache.
	// Zero or negative disables caching of denied decisions.
	denyTTL time.Duration
}

// newDecisionCache returns a bounded decision cache with the given TTLs, or
// nil (caching fully disabled) when neither TTL is positive.
func newDecisionCache(allowTTL, denyTTL time.Duration, size int, clock utilcache.Clock) *decisionCache {
	if allowTTL <= 0 && denyTTL <= 0 {
		return nil
	}
	return &decisionCache{
		lru:      utilcache.NewLRUExpireCacheWithClock(size, clock),
		allowTTL: allowTTL,
		denyTTL:  denyTTL,
	}
}

// key derives the cache key from the exact SubjectAccessReviewSpec submitted to
// the API server, via structured JSON serialization — the same scheme the
// upstream webhook authorizer uses. Because the key is the full serialized
// request (requester name, groups, extras, and every resource attribute), two
// distinct authorization questions can never collide the way naive string
// concatenation could, and any field that influences the SAR outcome is
// automatically part of the key. It reports ok=false when the decision must
// not be cached (cache disabled, marshal failure, or oversized spec).
func (c *decisionCache) key(spec *v1.SubjectAccessReviewSpec) (string, bool) {
	if c == nil {
		return "", false
	}
	b, err := json.Marshal(spec)
	if err != nil || len(b) > maxCacheKeySize {
		return "", false
	}
	return string(b), true
}

// get returns a cached decision for key and whether one was present and
// unexpired.
func (c *decisionCache) get(key string) (allowed, ok bool) {
	if c == nil {
		return false, false
	}
	v, ok := c.lru.Get(key)
	if !ok {
		return false, false
	}
	return v.(bool), true
}

// put stores a definitive decision under the TTL matching its class. A class
// whose TTL is not positive is never cached. Errors must not reach put — the
// caller only stores decisions from successful reviews.
func (c *decisionCache) put(key string, allowed bool) {
	if c == nil {
		return
	}
	ttl := c.denyTTL
	if allowed {
		ttl = c.allowTTL
	}
	if ttl <= 0 {
		return
	}
	c.lru.Add(key, allowed, ttl)
}
