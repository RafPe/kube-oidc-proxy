# Readiness Probe

> 47 nodes

## Key Concepts

- **probe_test.go** (20 connections) — `pkg/probe/probe_test.go`
- **HealthCheck** (11 connections) — `pkg/probe/probe.go`
- **newTestHealthCheck()** (10 connections) — `pkg/probe/probe_test.go`
- **NewServer()** (9 connections) — `pkg/probe/probe.go`
- **Server** (8 connections) — `pkg/probe/probe.go`
- **sync.Mutex** (7 connections)
- **pkg/probe/probe.go** (7 connections) — `pkg/probe/probe.go`
- **newTestHealthCheckWithAuther()** (7 connections) — `pkg/probe/probe_test.go`
- **TestServerNoGoroutineLeak()** (5 connections) — `pkg/probe/probe_test.go`
- **.handler()** (5 connections) — `pkg/probe/probe.go`
- **freePort()** (4 connections) — `pkg/probe/probe_test.go`
- **TestCheckContinuesProbingPendingAfterLatch()** (4 connections) — `pkg/probe/probe_test.go`
- **TestCheckDoesNotHoldLockDuringAuth()** (4 connections) — `pkg/probe/probe_test.go`
- **TestServerStartServesAndShutsDown()** (4 connections) — `pkg/probe/probe_test.go`
- **concurrentAuther** (4 connections) — `pkg/probe/probe_test.go`
- **fakeAuther** (4 connections) — `pkg/probe/probe_test.go`
- **.Check()** (4 connections) — `pkg/probe/probe.go`
- **timeoutError** (4 connections) — `pkg/probe/probe_test.go`
- **getOnly()** (3 connections) — `pkg/probe/probe.go`
- **stableGoroutines()** (3 connections) — `pkg/probe/probe_test.go`
- **TestCheckAlternatePhrasingKeepsPending()** (3 connections) — `pkg/probe/probe_test.go`
- **TestCheckNotReadyBeforeServing()** (3 connections) — `pkg/probe/probe_test.go`
- **TestCheckReadiness()** (3 connections) — `pkg/probe/probe_test.go`
- **TestCheckReadinessIsSticky()** (3 connections) — `pkg/probe/probe_test.go`
- **TestCheckReadyAfterServing()** (3 connections) — `pkg/probe/probe_test.go`
- *... and 22 more nodes in this community*

## Relationships

- [Options Unit Tests](Options_Unit_Tests.md) (15 shared connections)
- [SubjectAccessReview Fakes](SubjectAccessReview_Fakes.md) (4 shared connections)
- [Run Command & Authenticator Wiring](Run_Command_&_Authenticator_Wiring.md) (4 shared connections)
- [TokenReview Cache & E2E Polling](TokenReview_Cache_&_E2E_Polling.md) (2 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (1 shared connections)
- [Fake OIDC Issuer Server](Fake_OIDC_Issuer_Server.md) (1 shared connections)
- [Clock Abstraction](Clock_Abstraction.md) (1 shared connections)
- [Proxy Handlers & Access Logging](Proxy_Handlers_&_Access_Logging.md) (1 shared connections)

## Source Files

- `pkg/probe/probe.go`
- `pkg/probe/probe_test.go`

## Audit Trail

- EXTRACTED: 104 (97%)
- INFERRED: 3 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*