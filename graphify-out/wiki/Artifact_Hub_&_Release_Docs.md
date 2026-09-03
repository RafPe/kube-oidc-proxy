# Artifact Hub & Release Docs

> 16 nodes

## Key Concepts

- **Unified release workflow TDD evidence** (9 connections) — `docs/testing/unified-release.tdd.md`
- **docs/releases.md** (8 connections) — `.github/workflows/prepare-release.yml`
- **Release workflow (tag, publish image/chart, GitHub Release)** (7 connections) — `docs/releases.md`
- **Prepare Release workflow (release/next -> main)** (5 connections) — `docs/releases.md`
- **PR Release Metadata required check** (4 connections) — `docs/releases.md`
- **Publishing on Artifact Hub** (4 connections) — `docs/artifact-hub.md`
- **Cosign keyless signing of chart and image** (3 connections) — `docs/artifact-hub.md`
- **Helm install (OCI registry, local checkout, raw manifests)** (3 connections) — `docs/getting-started.md`
- **.changes/unreleased/*.yaml changelog fragments** (3 connections) — `docs/releases.md`
- **release/major|minor|patch|skip PR labels** (3 connections) — `docs/releases.md`
- **scripts/release-contract-check.sh** (3 connections) — `docs/releases.md`
- **Artifact Hub Verified Publisher ownership (artifacthub-repo.yml)** (2 connections) — `docs/artifact-hub.md`
- **Release recovery: never move a tag, fix forward** (2 connections) — `docs/releases.md`
- **oras push of Artifact Hub ownership metadata to GHCR** (1 connections) — `docs/artifact-hub.md`
- **Shell boilerplate header** (1 connections) — `hack/boilerplate/boilerplate.sh.txt`
- **Automatic Patch Log** (1 connections) — `patchlog.txt`

## Relationships

- [Docs: Multi-Issuer & Configuration](Docs-_Multi-Issuer_&_Configuration.md) (4 shared connections)
- [PR Templates & Release Approval Workflows](PR_Templates_&_Release_Approval_Workflows.md) (1 shared connections)

## Source Files

- `.github/workflows/prepare-release.yml`
- `docs/artifact-hub.md`
- `docs/getting-started.md`
- `docs/releases.md`
- `docs/testing/unified-release.tdd.md`
- `hack/boilerplate/boilerplate.sh.txt`
- `patchlog.txt`

## Audit Trail

- EXTRACTED: 25 (78%)
- INFERRED: 5 (16%)
- AMBIGUOUS: 2 (6%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*