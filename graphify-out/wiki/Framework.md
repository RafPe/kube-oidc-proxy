# Framework

> God node · 44 connections · `test/e2e/framework/framework.go`

**Community:** [E2E Framework Config & Helpers](E2E_Framework_Config_&_Helpers.md)

## Connections by Relation

### contains
- framework.go `EXTRACTED`

### method
- .Helper() `EXTRACTED`
- .AfterEach() `EXTRACTED`
- .DeployProxyWithExtras() `EXTRACTED`
- .NewProxyRestConfig() `EXTRACTED`
- .NewProxyClient() `EXTRACTED`
- .gatherProxyLogs() `EXTRACTED`
- .deleteResources() `EXTRACTED`
- .DeployProxyWith() `EXTRACTED`
- .BeforeEach() `EXTRACTED`
- .IssuerKeyBundle() `EXTRACTED`
- .ProxyKeyBundle() `EXTRACTED`
- .IssuerURL() `EXTRACTED`
- .ProxyURL() `EXTRACTED`
- .ClientID() `EXTRACTED`

### references
- [KeyBundle](KeyBundle.md) `EXTRACTED`
- net/url.URL `EXTRACTED`
- k8s.io/api/core/v1.Volume `EXTRACTED`
- Config `EXTRACTED`
- [Helper](Helper.md) `EXTRACTED`
- proxyGetPods() `EXTRACTED`
- NewFramework() `EXTRACTED`
- NewOrderedFramework() `EXTRACTED`
- singlePod() `EXTRACTED`
- expectUnauthorized() `EXTRACTED`
- newFramework() `EXTRACTED`
- k8s.io/client-go/kubernetes.Interface `EXTRACTED`
- k8s.io/api/core/v1.Namespace `EXTRACTED`
- proxyPod() `EXTRACTED`
- readAuditLog() `EXTRACTED`
- ExpectProxyAuthenticated() `EXTRACTED`
- newExecRestConfig() `EXTRACTED`
- testAuditLogs() `EXTRACTED`
- sendRequestToProxy() `EXTRACTED`
- tryImpersonationClient() `EXTRACTED`
- *…and 9 more `references` connection(s) not listed (lowest-degree first to go)*

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*