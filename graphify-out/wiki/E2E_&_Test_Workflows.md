# E2E & Test Workflows

> 12 nodes

## Key Concepts

- **e2e workflow** (9 connections) — `.github/workflows/e2e.yaml`
- **test:unit job** (6 connections) — `.github/workflows/test.yaml`
- **test:e2e:versions job** (5 connections) — `.github/workflows/e2e.yaml`
- **e2e-shards workflow** (5 connections) — `.github/workflows/e2e-shards.yaml`
- **verify-e2e-shards.sh** (4 connections) — `hack/verify-e2e-shards.sh`
- **test:e2e @ <version> job** (4 connections) — `.github/workflows/e2e.yaml`
- **Makefile** (4 connections) — `.github/workflows/release.yaml`
- **Ginkgo Shard Label Partitioning** (4 connections) — `.github/workflows/e2e-shards.yaml`
- **test:e2e aggregator job** (3 connections) — `.github/workflows/e2e.yaml`
- **test/e2e/versions/kubernetes-versions.json** (3 connections) — `.github/workflows/e2e.yaml`
- **Kubernetes Version Matrix from Manifest** (2 connections) — `.github/workflows/e2e.yaml`
- **verify-e2e-shards.sh script** (1 connections) — `hack/verify-e2e-shards.sh`

## Relationships

- [Lint, Fuzz & Mocks](Lint,_Fuzz_&_Mocks.md) (3 shared connections)
- [Release Workflow Jobs](Release_Workflow_Jobs.md) (3 shared connections)
- [PR Templates & Release Approval Workflows](PR_Templates_&_Release_Approval_Workflows.md) (2 shared connections)
- [Build, Sign & Publish Workflows](Build,_Sign_&_Publish_Workflows.md) (1 shared connections)
- [GitHub Actions OIDC E2E](GitHub_Actions_OIDC_E2E.md) (1 shared connections)

## Source Files

- `.github/workflows/e2e-shards.yaml`
- `.github/workflows/e2e.yaml`
- `.github/workflows/release.yaml`
- `.github/workflows/test.yaml`
- `hack/verify-e2e-shards.sh`

## Audit Trail

- EXTRACTED: 27 (90%)
- INFERRED: 3 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*