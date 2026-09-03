# Clock Abstraction

> 6 nodes

## Key Concepts

- **time.Time** (5 connections)
- **fakeClock** (5 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **.NewTokenPayloadForIdentity()** (3 connections) — `test/e2e/framework/helper/token.go`
- **.Now()** (2 connections) — `pkg/proxy/subjectaccessreview/cache_test.go`
- **realClock** (2 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **.Now()** (2 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`

## Relationships

- [E2E Kind Environment](E2E_Kind_Environment.md) (2 shared connections)
- [SAR Decision Cache Tests](SAR_Decision_Cache_Tests.md) (2 shared connections)
- [E2E Framework TLS & URLs](E2E_Framework_TLS_&_URLs.md) (1 shared connections)
- [Readiness Probe](Readiness_Probe.md) (1 shared connections)
- [SubjectAccessReview Impersonation Checks](SubjectAccessReview_Impersonation_Checks.md) (1 shared connections)

## Source Files

- `pkg/proxy/subjectaccessreview/cache_test.go`
- `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- `test/e2e/framework/helper/token.go`

## Audit Trail

- EXTRACTED: 13 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*