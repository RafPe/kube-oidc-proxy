# E2E Proxy Deployment

> 10 nodes

## Key Concepts

- **k8s.io/api/core/v1.Volume** (9 connections)
- **ProxyExtras** (6 connections) — `test/e2e/framework/helper/deploy.go`
- **.DeployProxyWithExtras()** (5 connections) — `test/e2e/framework/framework.go`
- **.DeployFakeAPIServer()** (5 connections) — `test/e2e/framework/helper/deploy.go`
- **.DeployProxyWith()** (3 connections) — `test/e2e/framework/framework.go`
- **nodePortFor()** (3 connections) — `test/e2e/framework/helper/deploy.go`
- **k8s.io/api/core/v1.Container** (2 connections)
- **k8s.io/api/core/v1.ServiceType** (2 connections)
- **deploy.go** (2 connections) — `test/e2e/framework/helper/deploy.go`
- **k8s.io/api/core/v1.VolumeMount** (1 connections)

## Relationships

- [E2E Framework TLS & URLs](E2E_Framework_TLS_&_URLs.md) (10 shared connections)
- [E2E Framework Config & Helpers](E2E_Framework_Config_&_Helpers.md) (4 shared connections)
- [E2E Auth Config Builder](E2E_Auth_Config_Builder.md) (1 shared connections)
- [E2E Kind Environment](E2E_Kind_Environment.md) (1 shared connections)

## Source Files

- `test/e2e/framework/framework.go`
- `test/e2e/framework/helper/deploy.go`

## Audit Trail

- EXTRACTED: 27 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*