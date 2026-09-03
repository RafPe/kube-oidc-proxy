# E2E Audit Log Cases

> 8 nodes

## Key Concepts

- **cases/audit/audit.go** (6 connections) — `test/e2e/suite/cases/audit/audit.go`
- **singlePod()** (5 connections) — `test/e2e/suite/cases/audit/audit.go`
- **proxyPod()** (4 connections) — `test/e2e/suite/cases/audit/audit.go`
- **readAuditLog()** (4 connections) — `test/e2e/suite/cases/audit/audit.go`
- **newExecRestConfig()** (3 connections) — `test/e2e/suite/cases/audit/audit.go`
- **testAuditLogs()** (3 connections) — `test/e2e/suite/cases/audit/audit.go`
- **k8s.io/api/core/v1.Pod** (2 connections)
- **deployProxyWithAuditLogFile()** (2 connections) — `test/e2e/suite/cases/audit/audit.go`

## Relationships

- [E2E Framework Config & Helpers](E2E_Framework_Config_&_Helpers.md) (6 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (1 shared connections)

## Source Files

- `test/e2e/suite/cases/audit/audit.go`

## Audit Trail

- EXTRACTED: 18 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*