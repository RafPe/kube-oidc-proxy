# SAR Decision Cache Tests

> 19 nodes

## Key Concepts

- **cache_test.go** (23 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **newCachedSAR()** (16 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **impersonateUserRequest()** (13 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **cacheTestRequester()** (11 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestCacheAllowHitAndExpiry()** (6 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestCacheDenyThenAllowAfterRBACChange()** (6 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestErrorsNeverCached()** (6 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestOversizedSpecNotCached()** (6 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestCacheDenyTTLZeroRechecksImmediately()** (5 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestDecisionCacheBound()** (5 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestSingleflightDedup()** (5 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestSingleflightWinnerCancellationDoesNotPoisonWaiters()** (5 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestCachedAllowNotInheritedAcrossUID()** (4 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestCachedAllowNotLeakedAcrossNaiveCollision()** (4 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestCacheDisabled()** (4 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **TestRequesterExtrasPartitionCache()** (4 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **.Advance()** (4 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **failWith()** (3 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **k8s.io/apiserver/pkg/authentication/user.DefaultInfo** (1 connections)

## Relationships

- [Options Unit Tests](Options_Unit_Tests.md) (12 shared connections)
- [SubjectAccessReview Fakes](SubjectAccessReview_Fakes.md) (6 shared connections)
- [Decision Cache](Decision_Cache.md) (4 shared connections)
- [SubjectAccessReview Impersonation Checks](SubjectAccessReview_Impersonation_Checks.md) (4 shared connections)
- [Clock Abstraction](Clock_Abstraction.md) (2 shared connections)
- [TokenReview Cache & E2E Polling](TokenReview_Cache_&_E2E_Polling.md) (2 shared connections)
- [Proxy Handlers & Access Logging](Proxy_Handlers_&_Access_Logging.md) (1 shared connections)

## Source Files

- `pkg/proxy/subjectaccessreview/cache_test.go`

## Audit Trail

- EXTRACTED: 77 (95%)
- INFERRED: 4 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*