# E2E Kubectl & Image Loading

> 18 nodes

## Key Concepts

- **Kind** (8 connections) — `test/kind/image.go`
- **Kubectl** (6 connections) — `test/e2e/framework/helper/kubectl.go`
- **.loadImage()** (6 connections) — `test/kind/image.go`
- **.LoadAllImages()** (5 connections) — `test/kind/image.go`
- **.Run()** (4 connections) — `test/e2e/framework/helper/kubectl.go`
- **.Describe()** (3 connections) — `test/e2e/framework/helper/kubectl.go`
- **.RunWithStdout()** (3 connections) — `test/e2e/framework/helper/kubectl.go`
- **.LoadAuditWebhook()** (3 connections) — `test/kind/image.go`
- **.LoadFakeAPIServer()** (3 connections) — `test/kind/image.go`
- **.LoadIssuer()** (3 connections) — `test/kind/image.go`
- **.LoadKubeOIDCProxy()** (3 connections) — `test/kind/image.go`
- **.runCmd()** (3 connections) — `test/kind/image.go`
- **.runCmdWithOut()** (3 connections) — `test/kind/image.go`
- **io.Writer** (2 connections)
- **.Kubectl()** (2 connections) — `test/e2e/framework/helper/kubectl.go`
- **.DescribeResource()** (2 connections) — `test/e2e/framework/helper/kubectl.go`
- **kubectl.go** (1 connections) — `test/e2e/framework/helper/kubectl.go`
- **Helper** (1 connections) — `test/e2e/framework/helper/kubectl.go`

## Relationships

- [E2E Framework Config & Helpers](E2E_Framework_Config_&_Helpers.md) (1 shared connections)

## Source Files

- `test/e2e/framework/helper/kubectl.go`
- `test/kind/image.go`

## Audit Trail

- EXTRACTED: 30 (97%)
- INFERRED: 1 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*