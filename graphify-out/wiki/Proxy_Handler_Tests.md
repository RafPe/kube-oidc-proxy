# Proxy Handler Tests

> 19 nodes

## Key Concepts

- **proxy_test.go** (14 connections) — `pkg/proxy/proxy_test.go`
- **fakeRW** (7 connections) — `pkg/proxy/proxy_test.go`
- **tryError()** (6 connections) — `pkg/proxy/proxy_test.go`
- **fakeProxy** (6 connections) — `pkg/proxy/proxy_test.go`
- **TestHandlers()** (4 connections) — `pkg/proxy/proxy_test.go`
- **TestHeadersConfig()** (4 connections) — `pkg/proxy/proxy_test.go`
- **fakeRT** (4 connections) — `pkg/proxy/proxy_test.go`
- **newFakeR()** (3 connections) — `pkg/proxy/proxy_test.go`
- **newFakeRW()** (3 connections) — `pkg/proxy/proxy_test.go`
- **TestError()** (3 connections) — `pkg/proxy/proxy_test.go`
- **TestRoundTripperForRestConfigReloadsClientCertificate()** (3 connections) — `pkg/proxy/proxy_test.go`
- **writeProxyClientKeyPair()** (3 connections) — `pkg/proxy/proxy_test.go`
- **TestHasImpersonation()** (2 connections) — `pkg/proxy/proxy_test.go`
- **.Header()** (2 connections) — `pkg/proxy/proxy_test.go`
- **github.com/rafpe/kube-oidc-proxy/pkg/mocks.MockToken** (1 connections)
- **go.uber.org/mock/gomock.Controller** (1 connections)
- **Proxy** (1 connections)
- **.Write()** (1 connections) — `pkg/proxy/proxy_test.go`
- **.WriteHeader()** (1 connections) — `pkg/proxy/proxy_test.go`

## Relationships

- [Options Unit Tests](Options_Unit_Tests.md) (8 shared connections)
- [Proxy Handlers & Access Logging](Proxy_Handlers_&_Access_Logging.md) (6 shared connections)
- [Reserved Identity Handler Tests](Reserved_Identity_Handler_Tests.md) (4 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (1 shared connections)

## Source Files

- `pkg/proxy/proxy_test.go`

## Audit Trail

- EXTRACTED: 44 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*