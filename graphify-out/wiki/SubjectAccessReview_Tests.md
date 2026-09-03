# SubjectAccessReview Tests

> 18 nodes

## Key Concepts

- **subjectaccessreview_test.go** (13 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **New()** (9 connections) — `pkg/proxy/subjectaccessreview/fake/subjectaccessreview.go`
- **FakeReviewer** (5 connections) — `pkg/proxy/subjectaccessreview/fake/subjectaccessreview.go`
- **impersonationHeaders()** (5 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **runTest()** (5 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **countingFakeReviewer** (4 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **TestCheckAuthorizedForImpersonationCanceled()** (3 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **TestCheckAuthorizedForImpersonationConfiguredTimeout()** (3 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **TestCheckAuthorizedForImpersonationDeadlineExceeded()** (3 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **TestCheckAuthorizedForImpersonationHeaderValueCap()** (3 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **TestNewRejectsNonPositiveMaxHeaderValues()** (3 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **TestSubjectAccessReview()** (3 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **blockingReviewer** (3 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **testT** (3 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **sync/atomic.Int32** (2 connections)
- **fake/subjectaccessreview.go** (2 connections) — `pkg/proxy/subjectaccessreview/fake/subjectaccessreview.go`
- **TestImpersonationAuthErrorClassification()** (2 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`
- **sarResult** (2 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`

## Relationships

- [Options Unit Tests](Options_Unit_Tests.md) (8 shared connections)
- [SubjectAccessReview Fakes](SubjectAccessReview_Fakes.md) (4 shared connections)
- [Reserved Identity Handler Tests](Reserved_Identity_Handler_Tests.md) (3 shared connections)
- [SubjectAccessReview Impersonation Checks](SubjectAccessReview_Impersonation_Checks.md) (2 shared connections)
- [Proxy Constructor Tests](Proxy_Constructor_Tests.md) (1 shared connections)
- [Proxy Handlers & Access Logging](Proxy_Handlers_&_Access_Logging.md) (1 shared connections)

## Source Files

- `pkg/proxy/subjectaccessreview/fake/subjectaccessreview.go`
- `pkg/proxy/subjectaccessreview/subjectaccessreview_test.go`

## Audit Trail

- EXTRACTED: 46 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*