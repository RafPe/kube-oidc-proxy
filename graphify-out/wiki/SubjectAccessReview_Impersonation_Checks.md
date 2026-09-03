# SubjectAccessReview Impersonation Checks

> 16 nodes

## Key Concepts

- **SubjectAccessReview** (13 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **k8s.io/apiserver/pkg/authentication/user.Info** (10 connections)
- **impersonationReviewSpec()** (7 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **.checkRbacImpersonationAuthorization()** (7 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **subjectaccessreview/subjectaccessreview.go** (6 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **.CheckAuthorizedForImpersonation()** (5 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **.liveCheck()** (5 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **.sharedLiveCheck()** (5 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **k8s.io/api/authorization/v1.SubjectAccessReviewSpec** (4 connections)
- **k8s.io/client-go/kubernetes/typed/authorization/v1.SubjectAccessReviewInterface** (3 connections)
- **countImpersonationHeaderValues()** (3 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **ImpersonationAuthError** (3 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **.key()** (2 connections) — `pkg/proxy/subjectaccessreview/cache.go`
- **golang.org/x/sync/singleflight.Group** (1 connections)
- **.Error()** (1 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **.Is()** (1 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`

## Relationships

- [Proxy Handlers & Access Logging](Proxy_Handlers_&_Access_Logging.md) (6 shared connections)
- [SAR Decision Cache Tests](SAR_Decision_Cache_Tests.md) (4 shared connections)
- [Reserved Identity Handler Tests](Reserved_Identity_Handler_Tests.md) (3 shared connections)
- [Decision Cache](Decision_Cache.md) (3 shared connections)
- [SubjectAccessReview Fakes](SubjectAccessReview_Fakes.md) (3 shared connections)
- [SubjectAccessReview Tests](SubjectAccessReview_Tests.md) (2 shared connections)
- [TokenReview Cache & E2E Polling](TokenReview_Cache_&_E2E_Polling.md) (2 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (2 shared connections)
- [Clock Abstraction](Clock_Abstraction.md) (1 shared connections)

## Source Files

- `pkg/proxy/subjectaccessreview/cache.go`
- `pkg/proxy/subjectaccessreview/subjectaccessreview.go`

## Audit Trail

- EXTRACTED: 48 (94%)
- INFERRED: 3 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*