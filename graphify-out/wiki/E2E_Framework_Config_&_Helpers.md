# E2E Framework Config & Helpers

> 23 nodes

## Key Concepts

- **Framework** (44 connections) — `test/e2e/framework/framework.go`
- **Config** (9 connections) — `test/e2e/framework/config/config.go`
- **framework.go** (7 connections) — `test/e2e/framework/framework.go`
- **.Helper()** (6 connections) — `test/e2e/framework/framework.go`
- **NewFramework()** (6 connections) — `test/e2e/framework/framework.go`
- **NewOrderedFramework()** (6 connections) — `test/e2e/framework/framework.go`
- **Helper** (6 connections) — `test/e2e/framework/helper/helper.go`
- **.AfterEach()** (5 connections) — `test/e2e/framework/framework.go`
- **newFramework()** (5 connections) — `test/e2e/framework/framework.go`
- **NewHelper()** (5 connections) — `test/e2e/framework/helper/helper.go`
- **.NewProxyClient()** (4 connections) — `test/e2e/framework/framework.go`
- **.NewProxyRestConfig()** (4 connections) — `test/e2e/framework/framework.go`
- **k8s.io/client-go/kubernetes.Interface** (4 connections)
- **.BeforeEach()** (3 connections) — `test/e2e/framework/framework.go`
- **.deleteResources()** (3 connections) — `test/e2e/framework/framework.go`
- **.gatherProxyLogs()** (3 connections) — `test/e2e/framework/framework.go`
- **NewDefaultFramework()** (3 connections) — `test/e2e/framework/framework.go`
- **NewOrderedDefaultFramework()** (3 connections) — `test/e2e/framework/framework.go`
- **CasesDescribe()** (2 connections) — `test/e2e/framework/framework.go`
- **helper.go** (2 connections) — `test/e2e/framework/helper/helper.go`
- **.Validate()** (1 connections) — `test/e2e/framework/config/config.go`
- **.ClientID()** (1 connections) — `test/e2e/framework/framework.go`
- **config.go** (1 connections) — `test/e2e/framework/config/config.go`

## Relationships

- [E2E Framework TLS & URLs](E2E_Framework_TLS_&_URLs.md) (7 shared connections)
- [E2E Audit Log Cases](E2E_Audit_Log_Cases.md) (6 shared connections)
- [E2E Proxy Deployment](E2E_Proxy_Deployment.md) (4 shared connections)
- [E2E Reserved Identity Case](E2E_Reserved_Identity_Case.md) (4 shared connections)
- [E2E Shared Token Tests](E2E_Shared_Token_Tests.md) (4 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (3 shared connections)
- [E2E Kind Environment](E2E_Kind_Environment.md) (2 shared connections)
- [E2E Namespace Utilities](E2E_Namespace_Utilities.md) (1 shared connections)
- [E2E Kubectl & Image Loading](E2E_Kubectl_&_Image_Loading.md) (1 shared connections)
- [E2E Impersonation Client](E2E_Impersonation_Client.md) (1 shared connections)

## Source Files

- `test/e2e/framework/config/config.go`
- `test/e2e/framework/framework.go`
- `test/e2e/framework/helper/helper.go`

## Audit Trail

- EXTRACTED: 82 (99%)
- INFERRED: 1 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*