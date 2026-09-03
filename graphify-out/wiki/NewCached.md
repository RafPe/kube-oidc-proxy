# NewCached()

> God node · 14 connections · `pkg/proxy/tokenreview/tokenreview.go`

**Community:** [TokenReview Cache Tests](TokenReview_Cache_Tests.md)

## Connections by Relation

### calls
- buildRunCommand() `EXTRACTED`
- newCachedTokenReview() `EXTRACTED`
- TestCachedReviewSeparatesAudienceSets() `INFERRED`
- TestNewCached() `INFERRED`
- TestCachedReviewBoundsEntryCount() `INFERRED`
- TestCachedReviewConcurrentMissesRunIndependently() `INFERRED`
- TestCachedReviewHonoursCallerCancellation() `INFERRED`
- TestCachedReviewHonoursTimeoutAboveThirtySeconds() `INFERRED`
- TestCachedReviewSendsConfiguredAudiences() `INFERRED`
- TestNewCachedZeroTTLsReturnsBareReviewer() `INFERRED`

### contains
- tokenreview/tokenreview.go `EXTRACTED`

### references
- time.Duration `EXTRACTED`
- k8s.io/apiserver/pkg/authentication/authenticator.Token `EXTRACTED`
- TokenReview `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*