# Release Workflow Jobs

> 7 nodes

## Key Concepts

- **release:verify job** (10 connections) — `.github/workflows/release.yaml`
- **Release workflow** (8 connections) — `.github/workflows/release.yaml`
- **release:check job** (5 connections) — `.github/workflows/release.yaml`
- **release:artifact job** (5 connections) — `.github/workflows/release.yaml`
- **release:tag job** (5 connections) — `.github/workflows/release.yaml`
- **release:e2e job** (4 connections) — `.github/workflows/release.yaml`
- **release:publish job** (4 connections) — `.github/workflows/release.yaml`

## Relationships

- [PR Templates & Release Approval Workflows](PR_Templates_&_Release_Approval_Workflows.md) (5 shared connections)
- [E2E & Test Workflows](E2E_&_Test_Workflows.md) (3 shared connections)
- [Build, Sign & Publish Workflows](Build,_Sign_&_Publish_Workflows.md) (2 shared connections)
- [Release Contract Check](Release_Contract_Check.md) (1 shared connections)

## Source Files

- `.github/workflows/release.yaml`

## Audit Trail

- EXTRACTED: 25 (96%)
- INFERRED: 1 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*