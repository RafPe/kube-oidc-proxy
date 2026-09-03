# E2E Framework TLS & URLs

> 23 nodes

## Key Concepts

- **KeyBundle** (16 connections) — `test/util/tls.go`
- **net/url.URL** (15 connections)
- **Helper** (13 connections) — `test/e2e/framework/helper/deploy.go`
- **.deployApp()** (12 connections) — `test/e2e/framework/helper/deploy.go`
- **.DeployProxyWithExtras()** (8 connections) — `test/e2e/framework/helper/deploy.go`
- **.DeployProxy()** (7 connections) — `test/e2e/framework/helper/deploy.go`
- **.DeployIssuer()** (5 connections) — `test/e2e/framework/helper/deploy.go`
- **.DeployNamedIssuer()** (5 connections) — `test/e2e/framework/helper/deploy.go`
- **k8s.io/api/core/v1.Namespace** (4 connections)
- **.deleteApp()** (4 connections) — `test/e2e/framework/helper/deploy.go`
- **.DeployAuditWebhook()** (4 connections) — `test/e2e/framework/helper/deploy.go`
- **NewTLSSelfSignedCertKey()** (4 connections) — `test/util/tls.go`
- **.DeleteNamedIssuer()** (3 connections) — `test/e2e/framework/helper/deploy.go`
- **.IssuerKeyBundle()** (2 connections) — `test/e2e/framework/framework.go`
- **.IssuerURL()** (2 connections) — `test/e2e/framework/framework.go`
- **.ProxyKeyBundle()** (2 connections) — `test/e2e/framework/framework.go`
- **.ProxyURL()** (2 connections) — `test/e2e/framework/framework.go`
- **.appURL()** (2 connections) — `test/e2e/framework/helper/deploy.go`
- **.DeleteFakeAPIServer()** (2 connections) — `test/e2e/framework/helper/deploy.go`
- **.DeleteIssuer()** (2 connections) — `test/e2e/framework/helper/deploy.go`
- **.DeleteProxy()** (2 connections) — `test/e2e/framework/helper/deploy.go`
- **tls.go** (2 connections) — `test/util/tls.go`
- **net.IP** (1 connections)

## Relationships

- [E2E Proxy Deployment](E2E_Proxy_Deployment.md) (10 shared connections)
- [E2E Framework Config & Helpers](E2E_Framework_Config_&_Helpers.md) (7 shared connections)
- [E2E Kind Environment](E2E_Kind_Environment.md) (6 shared connections)
- [E2E Shared Token Tests](E2E_Shared_Token_Tests.md) (3 shared connections)
- [E2E Namespace Utilities](E2E_Namespace_Utilities.md) (1 shared connections)
- [Clock Abstraction](Clock_Abstraction.md) (1 shared connections)
- [TokenReview Cache & E2E Polling](TokenReview_Cache_&_E2E_Polling.md) (1 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (1 shared connections)
- [Fake OIDC Issuer Server](Fake_OIDC_Issuer_Server.md) (1 shared connections)

## Source Files

- `test/e2e/framework/framework.go`
- `test/e2e/framework/helper/deploy.go`
- `test/util/tls.go`

## Audit Trail

- EXTRACTED: 75 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*