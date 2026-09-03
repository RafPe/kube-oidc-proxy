# Proxy Handlers & Access Logging

> 82 nodes

## Key Concepts

- **net/http.Request** (30 connections)
- **context.go** (16 connections) — `pkg/proxy/context/context.go`
- **accesslog.go** (14 connections) — `pkg/proxy/logging/accesslog.go`
- **net/http.Handler** (11 connections)
- **net.IPNet** (10 connections)
- **RemoteAddr()** (10 connections) — `pkg/proxy/context/context.go`
- **requestAttrs()** (10 connections) — `pkg/proxy/logging/accesslog.go`
- **net/http.Header** (9 connections)
- **net/http.ResponseWriter** (9 connections)
- **.withImpersonateRequest()** (9 connections) — `pkg/proxy/handlers.go`
- **NewForbiddenHandler()** (8 connections) — `pkg/proxy/audit/handler.go`
- **LogSuccessfulRequest()** (8 connections) — `pkg/proxy/logging/accesslog.go`
- **NewUnauthenticatedHandler()** (7 connections) — `pkg/proxy/audit/handler.go`
- **ResolveClientIP()** (7 connections) — `pkg/proxy/context/context.go`
- **SanitizeForwardHeaders()** (7 connections) — `pkg/proxy/context/context.go`
- **mustCIDRs()** (7 connections) — `pkg/proxy/context/context_test.go`
- **Proxy** (7 connections) — `pkg/proxy/handlers.go`
- **sanitize()** (7 connections) — `pkg/proxy/logging/accesslog.go`
- **accesslog_test.go** (7 connections) — `pkg/proxy/logging/accesslog_test.go`
- **userAttrs()** (7 connections) — `pkg/proxy/logging/accesslog.go`
- **.RoundTrip()** (7 connections) — `pkg/proxy/proxy_test.go`
- **.RoundTrip()** (7 connections) — `pkg/proxy/proxy.go`
- **SetTrustedProxies()** (6 connections) — `pkg/proxy/context/context.go`
- **context_test.go** (6 connections) — `pkg/proxy/context/context_test.go`
- **LogFailedRequest()** (6 connections) — `pkg/proxy/logging/accesslog.go`
- *... and 57 more nodes in this community*

## Relationships

- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (16 shared connections)
- [Options Unit Tests](Options_Unit_Tests.md) (16 shared connections)
- [SubjectAccessReview Impersonation Checks](SubjectAccessReview_Impersonation_Checks.md) (6 shared connections)
- [Proxy Handler Tests](Proxy_Handler_Tests.md) (6 shared connections)
- [Fake OIDC Issuer Server](Fake_OIDC_Issuer_Server.md) (5 shared connections)
- [Reserved Identity Handler Tests](Reserved_Identity_Handler_Tests.md) (3 shared connections)
- [Forbidden Handler Audit Tests](Forbidden_Handler_Audit_Tests.md) (3 shared connections)
- [Token Parsing Utilities](Token_Parsing_Utilities.md) (2 shared connections)
- [Readiness Probe](Readiness_Probe.md) (1 shared connections)
- [SubjectAccessReview Tests](SubjectAccessReview_Tests.md) (1 shared connections)
- [SAR Decision Cache Tests](SAR_Decision_Cache_Tests.md) (1 shared connections)

## Source Files

- `pkg/proxy/audit/handler.go`
- `pkg/proxy/context/context.go`
- `pkg/proxy/context/context_test.go`
- `pkg/proxy/handlers.go`
- `pkg/proxy/handlers_test.go`
- `pkg/proxy/logging/accesslog.go`
- `pkg/proxy/logging/accesslog_test.go`
- `pkg/proxy/proxy.go`
- `pkg/proxy/proxy_test.go`
- `test/tools/audit-webhook/pkg/sink/sink.go`
- `test/tools/fake-apiserver/pkg/server/server.go`
- `test/tools/fake-apiserver/pkg/server/server_test.go`

## Audit Trail

- EXTRACTED: 231 (92%)
- INFERRED: 19 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*