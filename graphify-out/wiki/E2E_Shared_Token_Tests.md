# E2E Shared Token Tests

> 5 nodes

## Key Concepts

- **proxyGetPods()** (6 connections) — `test/e2e/suite/cases/sharedtests/sharedtests.go`
- **expectUnauthorized()** (5 connections) — `test/e2e/suite/cases/sharedtests/sharedtests.go`
- **sharedtests.go** (4 connections) — `test/e2e/suite/cases/sharedtests/sharedtests.go`
- **ExpectProxyAuthenticated()** (4 connections) — `test/e2e/suite/cases/sharedtests/sharedtests.go`
- **RunTokenValidationTests()** (3 connections) — `test/e2e/suite/cases/sharedtests/sharedtests.go`

## Relationships

- [E2E Framework Config & Helpers](E2E_Framework_Config_&_Helpers.md) (4 shared connections)
- [E2E Framework TLS & URLs](E2E_Framework_TLS_&_URLs.md) (3 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (1 shared connections)

## Source Files

- `test/e2e/suite/cases/sharedtests/sharedtests.go`

## Audit Trail

- EXTRACTED: 15 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*