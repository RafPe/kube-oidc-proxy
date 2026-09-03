# Run Command & Authenticator Wiring

> 26 nodes

## Key Concepts

- **buildRunCommand()** (12 connections) — `cmd/app/run.go`
- **run.go** (11 connections) — `cmd/app/run.go`
- **k8s.io/apiserver/pkg/authentication/authenticator.Token** (11 connections)
- **buildTokenAuther()** (10 connections) — `cmd/app/run.go`
- **run_test.go** (10 connections) — `cmd/app/run_test.go`
- **oidcAutherFromJWT()** (8 connections) — `cmd/app/run.go`
- **buildSingleAuther()** (7 connections) — `cmd/app/run.go`
- **buildUnionAuther()** (5 connections) — `cmd/app/run.go`
- **jwtAuthenticatorFromOIDCOptions()** (5 connections) — `cmd/app/run.go`
- **NewRunCommand()** (5 connections) — `cmd/app/run.go`
- **oidcHTTPClient()** (5 connections) — `cmd/app/run.go`
- **checkReservedIdentityPrefixes()** (4 connections) — `cmd/app/run.go`
- **TestBuildTokenAuther_AuthConfig()** (4 connections) — `cmd/app/run_test.go`
- **TestOIDCHTTPClientReloadsClientCertificate()** (4 connections) — `cmd/app/run_test.go`
- **caContentProvider()** (3 connections) — `cmd/app/run.go`
- **TestBuildTokenAuther_AuthConfig_InvalidFile()** (3 connections) — `cmd/app/run_test.go`
- **TestBuildTokenAuther_SingleIssuer()** (3 connections) — `cmd/app/run_test.go`
- **TestCheckReservedIdentityPrefixes()** (3 connections) — `cmd/app/run_test.go`
- **TestJWTAuthenticatorFromOIDCOptions_RequiredClaims()** (3 connections) — `cmd/app/run_test.go`
- **TestOIDCAutherFromJWT_Construction()** (3 connections) — `cmd/app/run_test.go`
- **writeClientKeyPair()** (3 connections) — `cmd/app/run_test.go`
- **writeTempFile()** (3 connections) — `cmd/app/run_test.go`
- **caFromFile** (2 connections) — `cmd/app/run.go`
- **k8s.io/apiserver/pkg/apis/apiserver.JWTAuthenticator** (2 connections)
- **.CurrentCABundleContent()** (1 connections) — `cmd/app/run.go`
- *... and 1 more nodes in this community*

## Relationships

- [Options Unit Tests](Options_Unit_Tests.md) (9 shared connections)
- [Command Options](Command_Options.md) (6 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (5 shared connections)
- [Readiness Probe](Readiness_Probe.md) (4 shared connections)
- [OIDC Authentication Options](OIDC_Authentication_Options.md) (3 shared connections)
- [Misc Options & Version](Misc_Options_&_Version.md) (3 shared connections)
- [TokenReview Cache Tests](TokenReview_Cache_Tests.md) (2 shared connections)
- [TokenReview Cache & E2E Polling](TokenReview_Cache_&_E2E_Polling.md) (1 shared connections)
- [Reserved Identity Handler Tests](Reserved_Identity_Handler_Tests.md) (1 shared connections)
- [Token Parsing Utilities](Token_Parsing_Utilities.md) (1 shared connections)
- [Fake OIDC Issuer Server](Fake_OIDC_Issuer_Server.md) (1 shared connections)
- [Authentication Config Options](Authentication_Config_Options.md) (1 shared connections)

## Source Files

- `cmd/app/run.go`
- `cmd/app/run_test.go`

## Audit Trail

- EXTRACTED: 76 (90%)
- INFERRED: 8 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*