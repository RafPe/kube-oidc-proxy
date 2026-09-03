# Fake TokenReview

> 7 nodes

## Key Concepts

- **k8s.io/api/authentication/v1.TokenReview** (7 connections)
- **FakeReviewer** (7 connections) — `pkg/proxy/tokenreview/fake/tokenreview.go`
- **.Create()** (4 connections) — `pkg/proxy/tokenreview/fake/tokenreview.go`
- **New()** (4 connections) — `pkg/proxy/tokenreview/fake/tokenreview.go`
- **.CreateContext()** (3 connections) — `pkg/proxy/tokenreview/fake/tokenreview.go`
- **.WithCreate()** (2 connections) — `pkg/proxy/tokenreview/fake/tokenreview.go`
- **fake/tokenreview.go** (2 connections) — `pkg/proxy/tokenreview/fake/tokenreview.go`

## Relationships

- [SubjectAccessReview Fakes](SubjectAccessReview_Fakes.md) (4 shared connections)
- [TokenReview Cache Tests](TokenReview_Cache_Tests.md) (4 shared connections)
- [TokenReview Cache & E2E Polling](TokenReview_Cache_&_E2E_Polling.md) (1 shared connections)

## Source Files

- `pkg/proxy/tokenreview/fake/tokenreview.go`

## Audit Trail

- EXTRACTED: 19 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*