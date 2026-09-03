# E2E Kind Environment

> 50 nodes

## Key Concepts

- **Kind** (18 connections) — `test/kind/kind.go`
- **Environment** (11 connections) — `test/environment/environment.go`
- **deploy()** (10 connections) — `test/environment/dev/dev.go`
- **New()** (8 connections) — `test/environment/environment.go`
- **.NewValidRestConfig()** (6 connections) — `test/e2e/framework/helper/token.go`
- **versions.go** (6 connections) — `test/e2e/versions/versions.go`
- **.NewTokenPayload()** (5 connections) — `test/e2e/framework/helper/token.go`
- **.Create()** (5 connections) — `test/kind/kind.go`
- **.Destroy()** (5 connections) — `test/kind/kind.go`
- **Latest()** (5 connections) — `test/e2e/versions/versions.go`
- **dev.go** (5 connections) — `test/environment/dev/dev.go`
- **errExit()** (5 connections) — `test/environment/dev/dev.go`
- **main()** (5 connections) — `test/environment/dev/dev.go`
- **.SignToken()** (4 connections) — `test/e2e/framework/helper/token.go`
- **Helper** (4 connections) — `test/e2e/framework/helper/token.go`
- **TestImageFor()** (4 connections) — `test/e2e/versions/versions_test.go`
- **TestManifestIsValid()** (4 connections) — `test/e2e/versions/versions_test.go`
- **create()** (4 connections) — `test/environment/dev/dev.go`
- **destroy()** (4 connections) — `test/environment/dev/dev.go`
- **k8s.io/client-go/kubernetes.Clientset** (3 connections)
- **.errDestroy()** (3 connections) — `test/kind/kind.go`
- **.KubeConfigPath()** (3 connections) — `test/kind/kind.go`
- **.Nodes()** (3 connections) — `test/kind/kind.go`
- **.waitForCoreDNSReady()** (3 connections) — `test/kind/kind.go`
- **.waitForNodesReady()** (3 connections) — `test/kind/kind.go`
- *... and 25 more nodes in this community*

## Relationships

- [E2E Framework TLS & URLs](E2E_Framework_TLS_&_URLs.md) (6 shared connections)
- [Options Unit Tests](Options_Unit_Tests.md) (3 shared connections)
- [Clock Abstraction](Clock_Abstraction.md) (2 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (2 shared connections)
- [E2E Framework Config & Helpers](E2E_Framework_Config_&_Helpers.md) (2 shared connections)
- [E2E Proxy Deployment](E2E_Proxy_Deployment.md) (1 shared connections)

## Source Files

- `test/e2e/framework/helper/token.go`
- `test/e2e/versions/versions.go`
- `test/e2e/versions/versions_test.go`
- `test/environment/dev/dev.go`
- `test/environment/environment.go`
- `test/kind/kind.go`

## Audit Trail

- EXTRACTED: 97 (95%)
- INFERRED: 5 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*