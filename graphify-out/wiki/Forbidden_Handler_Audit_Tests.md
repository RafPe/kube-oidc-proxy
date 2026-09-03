# Forbidden Handler Audit Tests

> 7 nodes

## Key Concepts

- **handler_test.go** (6 connections) — `pkg/proxy/audit/handler_test.go`
- **readForbiddenAuditEvents()** (6 connections) — `pkg/proxy/audit/handler_test.go`
- **newForbiddenTestAudit()** (5 connections) — `pkg/proxy/audit/handler_test.go`
- **TestNewForbiddenHandlerAuditsAuthenticatedIdentity()** (5 connections) — `pkg/proxy/audit/handler_test.go`
- **TestNewUnauthenticatedHandlerAuditsFailedAuthentication()** (5 connections) — `pkg/proxy/audit/handler_test.go`
- **TestNewForbiddenHandlerWithoutAuditor()** (3 connections) — `pkg/proxy/audit/handler_test.go`
- **forbiddenAuditEvent** (2 connections) — `pkg/proxy/audit/handler_test.go`

## Relationships

- [Options Unit Tests](Options_Unit_Tests.md) (5 shared connections)
- [Proxy Handlers & Access Logging](Proxy_Handlers_&_Access_Logging.md) (3 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (2 shared connections)

## Source Files

- `pkg/proxy/audit/handler_test.go`

## Audit Trail

- EXTRACTED: 18 (86%)
- INFERRED: 3 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*