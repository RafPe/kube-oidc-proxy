# Decision Cache

> 7 nodes

## Key Concepts

- **newDecisionCache()** (8 connections) — `pkg/proxy/subjectaccessreview/cache.go`
- **decisionCache** (8 connections) — `pkg/proxy/subjectaccessreview/cache.go`
- **TestDecisionCacheKeyCollisionResistance()** (4 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **k8s.io/apimachinery/pkg/util/cache.Clock** (2 connections)
- **cache.go** (2 connections) — `pkg/proxy/subjectaccessreview/cache.go`
- **.get()** (1 connections) — `pkg/proxy/subjectaccessreview/cache.go`
- **.put()** (1 connections) — `pkg/proxy/subjectaccessreview/cache.go`

## Relationships

- [SAR Decision Cache Tests](SAR_Decision_Cache_Tests.md) (4 shared connections)
- [TokenReview Cache & E2E Polling](TokenReview_Cache_&_E2E_Polling.md) (3 shared connections)
- [SubjectAccessReview Impersonation Checks](SubjectAccessReview_Impersonation_Checks.md) (3 shared connections)
- [Reserved Identity Handler Tests](Reserved_Identity_Handler_Tests.md) (1 shared connections)
- [Options Unit Tests](Options_Unit_Tests.md) (1 shared connections)

## Source Files

- `pkg/proxy/subjectaccessreview/cache.go`
- `pkg/proxy/subjectaccessreview/cache_test.go`

## Audit Trail

- EXTRACTED: 14 (74%)
- INFERRED: 5 (26%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*