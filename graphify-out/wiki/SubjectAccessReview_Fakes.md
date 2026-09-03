# SubjectAccessReview Fakes

> 18 nodes

## Key Concepts

- **context.Context** (18 connections)
- **k8s.io/api/authorization/v1.SubjectAccessReview** (12 connections)
- **k8s.io/apimachinery/pkg/apis/meta/v1.CreateOptions** (8 connections)
- **fnReviewer** (6 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **.Create()** (5 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **.Create()** (5 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **sync/atomic.Int64** (4 connections)
- **.Create()** (4 connections) — `pkg/proxy/subjectaccessreview/fake/subjectaccessreview.go`
- **countingReviewer** (4 connections) — `pkg/proxy/handlers_test.go`
- **.Create()** (4 connections) — `pkg/proxy/handlers_test.go`
- **.Create()** (4 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **.Create()** (4 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **.Create()** (4 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **gatedReviewer** (3 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **winnerCancelReviewer** (3 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **allowAll()** (2 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **denyAll()** (2 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **.set()** (2 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`

## Relationships

- [SAR Decision Cache Tests](SAR_Decision_Cache_Tests.md) (6 shared connections)
- [Fake TokenReview](Fake_TokenReview.md) (4 shared connections)
- [Readiness Probe](Readiness_Probe.md) (4 shared connections)
- [SubjectAccessReview Tests](SubjectAccessReview_Tests.md) (4 shared connections)
- [SubjectAccessReview Impersonation Checks](SubjectAccessReview_Impersonation_Checks.md) (3 shared connections)
- [TokenReview Cache & E2E Polling](TokenReview_Cache_&_E2E_Polling.md) (2 shared connections)
- [Reserved Identity Handler Tests](Reserved_Identity_Handler_Tests.md) (1 shared connections)

## Source Files

- `pkg/proxy/handlers_test.go`
- `pkg/proxy/subjectaccessreview/cache_test.go`
- `pkg/proxy/subjectaccessreview/fake/subjectaccessreview.go`
- `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`

## Audit Trail

- EXTRACTED: 59 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*