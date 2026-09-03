# Reserved Identity Handler Tests

> 11 nodes

## Key Concepts

- **newTestProxy()** (14 connections) — `pkg/proxy/proxy_test.go`
- **handlers_test.go** (10 connections) — `pkg/proxy/handlers_test.go`
- **New()** (10 connections) — `pkg/proxy/subjectaccessreview/subjectaccessreview.go`
- **reservedIdentityRequest()** (8 connections) — `pkg/proxy/handlers_test.go`
- **TestOverCapImpersonationRejectedBeforeSubjectAccessReview()** (6 connections) — `pkg/proxy/handlers_test.go`
- **TestReservedIdentityRejectedBeforeSubjectAccessReview()** (6 connections) — `pkg/proxy/handlers_test.go`
- **TestWithAuthenticateRequestLogsValidationFailureAtV2()** (5 connections) — `pkg/proxy/handlers_test.go`
- **captureKlogAtV2()** (4 connections) — `pkg/proxy/handlers_test.go`
- **TestWithAuthenticateRequestAllowsAllowlistedReservedGroup()** (4 connections) — `pkg/proxy/handlers_test.go`
- **TestWithAuthenticateRequestRejectsReservedIdentity()** (4 connections) — `pkg/proxy/handlers_test.go`
- **TestWithImpersonateRequestDoesNotMutateAuthenticatorUser()** (2 connections) — `pkg/proxy/handlers_test.go`

## Relationships

- [Options Unit Tests](Options_Unit_Tests.md) (9 shared connections)
- [Proxy Handler Tests](Proxy_Handler_Tests.md) (4 shared connections)
- [Proxy Handlers & Access Logging](Proxy_Handlers_&_Access_Logging.md) (3 shared connections)
- [SubjectAccessReview Tests](SubjectAccessReview_Tests.md) (3 shared connections)
- [SubjectAccessReview Impersonation Checks](SubjectAccessReview_Impersonation_Checks.md) (3 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (2 shared connections)
- [SubjectAccessReview Fakes](SubjectAccessReview_Fakes.md) (1 shared connections)
- [Run Command & Authenticator Wiring](Run_Command_&_Authenticator_Wiring.md) (1 shared connections)
- [Proxy Constructor Tests](Proxy_Constructor_Tests.md) (1 shared connections)
- [TokenReview Cache & E2E Polling](TokenReview_Cache_&_E2E_Polling.md) (1 shared connections)
- [Decision Cache](Decision_Cache.md) (1 shared connections)

## Source Files

- `pkg/proxy/handlers_test.go`
- `pkg/proxy/proxy_test.go`
- `pkg/proxy/subjectaccessreview/subjectaccessreview.go`

## Audit Trail

- EXTRACTED: 45 (88%)
- INFERRED: 6 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*