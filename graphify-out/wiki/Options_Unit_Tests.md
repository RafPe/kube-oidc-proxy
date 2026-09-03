# Options Unit Tests

> 32 nodes

## Key Concepts

- **testing.T** (127 connections)
- **options_test.go** (6 connections) — `cmd/app/options/options_test.go`
- **hooks_test.go** (4 connections) — `pkg/proxy/hooks/hooks_test.go`
- **server_test.go** (4 connections) — `test/tools/fake-apiserver/pkg/server/server_test.go`
- **authentication_config_test.go** (3 connections) — `cmd/app/options/authentication_config_test.go`
- **TestAuthenticationConfigLoad()** (3 connections) — `cmd/app/options/authentication_config_test.go`
- **writeAuthConfig()** (3 connections) — `cmd/app/options/authentication_config_test.go`
- **TestAuthenticationConfigLoadMissingFile()** (2 connections) — `cmd/app/options/authentication_config_test.go`
- **oidc_test.go** (2 connections) — `cmd/app/options/oidc_test.go`
- **TestOIDCAuthenticationOptions_Validate()** (2 connections) — `cmd/app/options/oidc_test.go`
- **TestOIDCAuthenticationOptionsValidateTLSClientCredentials()** (2 connections) — `cmd/app/options/oidc_test.go`
- **TestOidcFlagsChanged()** (2 connections) — `cmd/app/options/options_test.go`
- **TestValidate_MaxImpersonationHeaderValues()** (2 connections) — `cmd/app/options/options_test.go`
- **TestValidate_MutualExclusivity()** (2 connections) — `cmd/app/options/options_test.go`
- **TestValidate_SubjectAccessReviewCacheTTLs()** (2 connections) — `cmd/app/options/options_test.go`
- **TestValidate_SubjectAccessReviewTimeout()** (2 connections) — `cmd/app/options/options_test.go`
- **TestValidate_TokenPassthroughCacheTTLs()** (2 connections) — `cmd/app/options/options_test.go`
- **audit_test.go** (2 connections) — `pkg/proxy/audit/audit_test.go`
- **TestLongRunningRequests()** (2 connections) — `pkg/proxy/audit/audit_test.go`
- **TestRequestInfoLongRunning()** (2 connections) — `pkg/proxy/audit/audit_test.go`
- **TestAddPreShutdownHookOverwritesInPlace()** (2 connections) — `pkg/proxy/hooks/hooks_test.go`
- **TestRunPreShutdownHooksDoesNotHoldLock()** (2 connections) — `pkg/proxy/hooks/hooks_test.go`
- **TestRunPreShutdownHooksNoHooks()** (2 connections) — `pkg/proxy/hooks/hooks_test.go`
- **TestRunPreShutdownHooksOrderAndContinuation()** (2 connections) — `pkg/proxy/hooks/hooks_test.go`
- **reviewtoken_test.go** (2 connections) — `pkg/proxy/reviewtoken_test.go`
- *... and 7 more nodes in this community*

## Relationships

- [Proxy Handlers & Access Logging](Proxy_Handlers_&_Access_Logging.md) (16 shared connections)
- [Readiness Probe](Readiness_Probe.md) (15 shared connections)
- [SAR Decision Cache Tests](SAR_Decision_Cache_Tests.md) (12 shared connections)
- [TokenReview Cache Tests](TokenReview_Cache_Tests.md) (11 shared connections)
- [Run Command & Authenticator Wiring](Run_Command_&_Authenticator_Wiring.md) (9 shared connections)
- [Reserved Identity Handler Tests](Reserved_Identity_Handler_Tests.md) (9 shared connections)
- [Proxy Handler Tests](Proxy_Handler_Tests.md) (8 shared connections)
- [SubjectAccessReview Tests](SubjectAccessReview_Tests.md) (8 shared connections)
- [Forbidden Handler Audit Tests](Forbidden_Handler_Audit_Tests.md) (5 shared connections)
- [Proxy Constructor Tests](Proxy_Constructor_Tests.md) (3 shared connections)
- [E2E Kind Environment](E2E_Kind_Environment.md) (3 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (2 shared connections)

## Source Files

- `cmd/app/options/authentication_config_test.go`
- `cmd/app/options/oidc_test.go`
- `cmd/app/options/options_test.go`
- `pkg/proxy/audit/audit_test.go`
- `pkg/proxy/hooks/hooks_test.go`
- `pkg/proxy/reviewtoken_test.go`
- `pkg/util/flags/string_to_string_slice_test.go`
- `test/tools/fake-apiserver/pkg/server/server_test.go`

## Audit Trail

- EXTRACTED: 152 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*