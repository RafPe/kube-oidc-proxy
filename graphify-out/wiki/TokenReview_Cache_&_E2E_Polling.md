# TokenReview Cache & E2E Polling

> 25 nodes

## Key Concepts

- **time.Duration** (19 connections)
- **TokenReview** (10 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **tokenreview/tokenreview.go** (9 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **cachedTokenReview** (7 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **.AuthenticateToken()** (7 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **k8s.io/apiserver/pkg/authentication/authenticator.Response** (5 connections)
- **cacheKey()** (5 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **New()** (5 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **newCachedTokenReview()** (5 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **.AuthenticateToken()** (5 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **userInfoFrom()** (4 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **Helper** (4 connections) — `test/e2e/framework/helper/poll.go`
- **.WaitForURLToBeReady()** (3 connections) — `test/e2e/framework/helper/poll.go`
- **writeLengthPrefixed()** (3 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **.buildReview()** (3 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **.reviewTimeout()** (3 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **k8s.io/apimachinery/pkg/util/cache.LRUExpireCache** (2 connections)
- **sync.Pool** (2 connections)
- **.WaitForDeploymentReady()** (2 connections) — `test/e2e/framework/helper/poll.go`
- **.WaitForDeploymentToDelete()** (2 connections) — `test/e2e/framework/helper/poll.go`
- **.WaitForPodReady()** (2 connections) — `test/e2e/framework/helper/poll.go`
- **cachedReview** (2 connections) — `pkg/proxy/tokenreview/tokenreview.go`
- **hash.Hash** (1 connections)
- **k8s.io/api/authentication/v1.UserInfo** (1 connections)
- **k8s.io/client-go/kubernetes/typed/authentication/v1.TokenReviewInterface** (1 connections)

## Relationships

- [TokenReview Cache Tests](TokenReview_Cache_Tests.md) (5 shared connections)
- [Decision Cache](Decision_Cache.md) (3 shared connections)
- [Readiness Probe](Readiness_Probe.md) (2 shared connections)
- [App Options & Flags](App_Options_&_Flags.md) (2 shared connections)
- [SubjectAccessReview Impersonation Checks](SubjectAccessReview_Impersonation_Checks.md) (2 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (2 shared connections)
- [SAR Decision Cache Tests](SAR_Decision_Cache_Tests.md) (2 shared connections)
- [SubjectAccessReview Fakes](SubjectAccessReview_Fakes.md) (2 shared connections)
- [Reserved Identity Handler Tests](Reserved_Identity_Handler_Tests.md) (1 shared connections)
- [E2E Framework TLS & URLs](E2E_Framework_TLS_&_URLs.md) (1 shared connections)
- [Run Command & Authenticator Wiring](Run_Command_&_Authenticator_Wiring.md) (1 shared connections)
- [Fake TokenReview](Fake_TokenReview.md) (1 shared connections)

## Source Files

- `pkg/proxy/tokenreview/tokenreview.go`
- `test/e2e/framework/helper/poll.go`

## Audit Trail

- EXTRACTED: 67 (99%)
- INFERRED: 1 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*