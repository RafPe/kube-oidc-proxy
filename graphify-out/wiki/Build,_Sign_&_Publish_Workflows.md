# Build, Sign & Publish Workflows

> 13 nodes

## Key Concepts

- **release-image chart job** (5 connections) — `.github/workflows/release-image.yaml`
- **release-image image job** (5 connections) — `.github/workflows/release-image.yaml`
- **release-image workflow** (5 connections) — `.github/workflows/release-image.yaml`
- **version-ldflags.sh** (4 connections) — `hack/version-ldflags.sh`
- **build:image job** (4 connections) — `.github/workflows/build.yaml`
- **build workflow** (4 connections) — `.github/workflows/build.yaml`
- **helm-chart workflow** (4 connections) — `.github/workflows/helm.yaml`
- **Cosign Keyless Signing and SBOM Attachment** (3 connections) — `.github/workflows/build.yaml`
- **chart/kube-oidc-proxy/Chart.yaml** (2 connections) — `.github/workflows/release-image.yaml`
- **KUBE_ROOT** (1 connections) — `hack/version-ldflags.sh`
- **version-ldflags.sh script** (1 connections) — `hack/version-ldflags.sh`
- **chart/kube-oidc-proxy/ci/multi-issuer-values.yaml** (1 connections) — `.github/workflows/helm.yaml`
- **chart/kube-oidc-proxy/ci/single-issuer-values.yaml** (1 connections) — `.github/workflows/helm.yaml`

## Relationships

- [Release Workflow Jobs](Release_Workflow_Jobs.md) (2 shared connections)
- [E2E & Test Workflows](E2E_&_Test_Workflows.md) (1 shared connections)
- [Lint, Fuzz & Mocks](Lint,_Fuzz_&_Mocks.md) (1 shared connections)

## Source Files

- `.github/workflows/build.yaml`
- `.github/workflows/helm.yaml`
- `.github/workflows/release-image.yaml`
- `hack/version-ldflags.sh`

## Audit Trail

- EXTRACTED: 19 (86%)
- INFERRED: 3 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*