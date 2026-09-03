# TokenReview Cache Tests

> 15 nodes

## Key Concepts

- **NewCached()** (14 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **tokenreview_test.go** (13 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **authenticatedReview()** (8 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **TestCachedReviewSeparatesAudienceSets()** (5 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **TestNewCached()** (5 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **unauthenticatedReview()** (5 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **TestCachedReviewBoundsEntryCount()** (4 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **TestCachedReviewConcurrentMissesRunIndependently()** (4 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **TestCachedReviewHonoursCallerCancellation()** (4 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **TestCachedReviewHonoursTimeoutAboveThirtySeconds()** (4 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **TestCachedReviewSendsConfiguredAudiences()** (4 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **TestNewCachedZeroTTLsReturnsBareReviewer()** (4 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **TestAuthenticateToken()** (3 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **TestCacheKey()** (3 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`
- **TestReviewTimeout()** (2 connections) — `pkg/proxy/tokenreview/tokenreview_test.go`

## Relationships

- [Options Unit Tests](Options_Unit_Tests.md) (11 shared connections)
- [TokenReview Cache & E2E Polling](TokenReview_Cache_&_E2E_Polling.md) (5 shared connections)
- [Fake TokenReview](Fake_TokenReview.md) (4 shared connections)
- [Run Command & Authenticator Wiring](Run_Command_&_Authenticator_Wiring.md) (2 shared connections)

## Source Files

- `pkg/proxy/tokenreview/tokenreview.go`
- `pkg/proxy/tokenreview/tokenreview_test.go`

## Audit Trail

- EXTRACTED: 43 (83%)
- INFERRED: 9 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*