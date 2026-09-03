# PR Templates & Release Approval Workflows

> 14 nodes

## Key Concepts

- **Prepare Release workflow** (9 connections) — `.github/workflows/prepare-release.yml`
- **PR Release Metadata workflow** (7 connections) — `.github/workflows/pr-release-metadata.yml`
- **release/next Branch** (5 connections) — `.github/workflows/prepare-release.yml`
- **Pull Request Template** (5 connections) — `.github/PULL_REQUEST_TEMPLATE.md`
- **review:release-approve job** (4 connections) — `.github/workflows/claude-review.yaml`
- **Changelog Fragment (.changes/unreleased/*.yaml)** (4 connections) — `.github/workflows/pr-release-metadata.yml`
- **autorelease: pending Label** (4 connections) — `.github/workflows/prepare-release.yml`
- **Release Drafter Config** (4 connections) — `.github/release-drafter.yml`
- **review:claude job** (3 connections) — `.github/workflows/claude-review.yaml`
- **release/* PR Labels** (3 connections) — `.github/release-drafter.yml`
- **Claude Review workflow** (3 connections) — `.github/workflows/claude-review.yaml`
- **.github/scripts/approve-release-pr.sh** (2 connections) — `.github/workflows/claude-review.yaml`
- **CHANGELOG.md** (2 connections) — `.github/workflows/prepare-release.yml`
- **Untrusted PR Content / Fork No-Auto-Approve Guard** (1 connections) — `.github/workflows/claude-review.yaml`

## Relationships

- [Release Workflow Jobs](Release_Workflow_Jobs.md) (5 shared connections)
- [E2E & Test Workflows](E2E_&_Test_Workflows.md) (2 shared connections)
- [Artifact Hub & Release Docs](Artifact_Hub_&_Release_Docs.md) (1 shared connections)

## Source Files

- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/release-drafter.yml`
- `.github/workflows/claude-review.yaml`
- `.github/workflows/pr-release-metadata.yml`
- `.github/workflows/prepare-release.yml`

## Audit Trail

- EXTRACTED: 29 (91%)
- INFERRED: 3 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*