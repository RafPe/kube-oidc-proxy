# Proxy Core: Audit & Serving

> 49 nodes

## Key Concepts

- **Proxy** (21 connections) — `pkg/proxy/proxy.go`
- **Audit** (13 connections) — `pkg/proxy/audit/audit.go`
- **k8s.io/client-go/rest.Config** (10 connections)
- **New()** (9 connections) — `pkg/proxy/proxy.go`
- **Dependencies** (9 connections) — `pkg/proxy/proxy.go`
- **proxy.go** (8 connections) — `pkg/proxy/proxy.go`
- **Hooks** (7 connections) — `pkg/proxy/hooks/hooks.go`
- **net/http.Response** (6 connections)
- **Requester** (6 connections) — `test/e2e/framework/helper/requester.go`
- **New()** (6 connections) — `pkg/proxy/audit/audit.go`
- **parseTrustedProxies()** (5 connections) — `pkg/proxy/proxy.go`
- **net/http.RoundTripper** (4 connections)
- **hooks.go** (4 connections) — `pkg/proxy/hooks/hooks.go`
- **New()** (4 connections) — `pkg/proxy/hooks/hooks.go`
- **parseAllowedReservedGroups()** (4 connections) — `pkg/proxy/proxy.go`
- **Config** (4 connections) — `pkg/proxy/proxy.go`
- **.roundTripperForRestConfig()** (4 connections) — `pkg/proxy/proxy.go`
- **portForwardOptions** (4 connections) — `test/e2e/suite/cases/upgrade/upgrade.go`
- **k8s.io/apimachinery/pkg/util/sets.Set** (3 connections)
- **k8s.io/apiserver/pkg/server.SecureServingInfo** (3 connections)
- **.NewRequester()** (3 connections) — `test/e2e/framework/helper/requester.go`
- **.RoundTrip()** (3 connections) — `test/e2e/framework/helper/requester.go`
- **hookEntry** (3 connections) — `pkg/proxy/hooks/hooks.go`
- **ShutdownHook** (3 connections) — `pkg/proxy/hooks/hooks.go`
- **TestParseAllowedReservedGroups()** (3 connections) — `pkg/proxy/proxy_test.go`
- *... and 24 more nodes in this community*

## Relationships

- [Proxy Handlers & Access Logging](Proxy_Handlers_&_Access_Logging.md) (16 shared connections)
- [Run Command & Authenticator Wiring](Run_Command_&_Authenticator_Wiring.md) (5 shared connections)
- [E2E Framework Config & Helpers](E2E_Framework_Config_&_Helpers.md) (3 shared connections)
- [Audit Options](Audit_Options.md) (3 shared connections)
- [E2E Kind Environment](E2E_Kind_Environment.md) (2 shared connections)
- [TokenReview Cache & E2E Polling](TokenReview_Cache_&_E2E_Polling.md) (2 shared connections)
- [Forbidden Handler Audit Tests](Forbidden_Handler_Audit_Tests.md) (2 shared connections)
- [Reserved Identity Handler Tests](Reserved_Identity_Handler_Tests.md) (2 shared connections)
- [SubjectAccessReview Impersonation Checks](SubjectAccessReview_Impersonation_Checks.md) (2 shared connections)
- [Options Unit Tests](Options_Unit_Tests.md) (2 shared connections)
- [E2E Audit Log Cases](E2E_Audit_Log_Cases.md) (1 shared connections)
- [E2E Shared Token Tests](E2E_Shared_Token_Tests.md) (1 shared connections)

## Source Files

- `pkg/proxy/audit/audit.go`
- `pkg/proxy/hooks/hooks.go`
- `pkg/proxy/proxy.go`
- `pkg/proxy/proxy_test.go`
- `pkg/proxy/trustedproxies_test.go`
- `test/e2e/framework/helper/requester.go`
- `test/e2e/suite/cases/headers/headers.go`
- `test/e2e/suite/cases/upgrade/upgrade.go`

## Audit Trail

- EXTRACTED: 116 (97%)
- INFERRED: 3 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*