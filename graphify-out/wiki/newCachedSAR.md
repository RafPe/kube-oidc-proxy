# newCachedSAR()

> God node · 16 connections · `pkg/proxy/subjectaccessreview/cache_test.go`

**Community:** [SAR Decision Cache Tests](SAR_Decision_Cache_Tests.md)

## Connections by Relation

### calls
- newDecisionCache() `INFERRED`
- TestCacheAllowHitAndExpiry() `EXTRACTED`
- TestCacheDenyThenAllowAfterRBACChange() `EXTRACTED`
- TestErrorsNeverCached() `EXTRACTED`
- TestOversizedSpecNotCached() `EXTRACTED`
- TestCacheDenyTTLZeroRechecksImmediately() `EXTRACTED`
- TestSingleflightDedup() `EXTRACTED`
- TestSingleflightWinnerCancellationDoesNotPoisonWaiters() `EXTRACTED`
- TestCachedAllowNotInheritedAcrossUID() `EXTRACTED`
- TestCachedAllowNotLeakedAcrossNaiveCollision() `EXTRACTED`
- TestRequesterExtrasPartitionCache() `EXTRACTED`

### contains
- cache_test.go `EXTRACTED`

### references
- time.Duration `EXTRACTED`
- SubjectAccessReview `EXTRACTED`
- k8s.io/client-go/kubernetes/typed/authorization/v1.SubjectAccessReviewInterface `EXTRACTED`
- k8s.io/apimachinery/pkg/util/cache.Clock `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*