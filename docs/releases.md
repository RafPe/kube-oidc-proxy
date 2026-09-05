# Releases

Ordinary pull requests never publish a release. This repository uses the same
review-gated release contract as the other RafPe Go projects.

- [Release model](#release-model)
- [Contributor metadata](#contributor-metadata)
- [Cutting a release](#cutting-a-release)
- [Recovery](#recovery)
- [Repository setup](#repository-setup)
- [Maintainer checks](#maintainer-checks)
- [Artifact Hub](#artifact-hub)
  - [One-time setup](#one-time-setup)
  - [Keeping the listing fresh](#keeping-the-listing-fresh)

## Release model

| Concept | Contract |
| --- | --- |
| Release metadata | Every ordinary PR has exactly one `release/major`, `release/minor`, `release/patch`, or `release/skip` label. |
| Changelog | Every non-skip PR adds `.changes/unreleased/*.yaml`; skip PRs add none. |
| Prepare Release | A manual, serialized workflow computes the next version, batches fragments, and opens or updates `release/next -> main`. It does not publish. |
| Approval | A maintainer reviews and merges that PR with `autorelease: pending`. |
| Verification | Unit checks and every Kind E2E shard run against the exact merge commit before a tag exists. |
| Publication | A serialized workflow creates an annotated immutable tag, publishes the signed image and chart, then publishes the draft GitHub Release. |

The highest label since the previous release wins: `major > minor > patch`.
Only-skip changes do not produce a release.

## Contributor metadata

Use a fragment such as:

```yaml
kind: Fixed
body: Preserve request cancellation while an authorization review is running.
```

Allowed kinds are `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`,
`Security`, and `Dependencies`. Keep the body user-facing and never include
credentials. The required **PR Release Metadata** check enforces the label and
fragment relationship. The generated release PR is narrowly exempt only when
its repository, branch, and `autorelease: pending` label all match.

## Cutting a release

1. Confirm all intended PR labels and fragments, then merge them.
2. Run **Actions -> Prepare Release -> Run workflow** on `main`:

   ```sh
   gh workflow run prepare-release.yml --ref main
   ```

3. Review the generated release PR's version, notes, and `CHANGELOG.md` section.
4. Merge the PR. That merge is the human publication approval.
5. Watch **Release** verify the exact merge SHA, run `make verify test`, execute
   all reusable E2E shards, create the tag, publish artifacts, and finally make
   the GitHub Release public.
6. Verify the GitHub Release, GHCR image/signature/SBOM, and OCI chart.

## Recovery

Never delete or move a release tag. If publication fails after tag creation,
fix forward on `main` and dispatch **Release** with the existing `vX.Y.Z` tag.
The workflow verifies that tag belongs to `main`, reruns checks and E2E, and
resumes publication. It refuses to move a tag or overwrite an already published
release.

## Repository setup

Prepare Release depends on repository state that is not in this repository.
Both of the following must be in place or the workflow pushes `release/next`
and then fails without opening a PR.

Create the four `release/*` labels and `autorelease: pending`:

```sh
for label in release/major release/minor release/patch release/skip; do
  gh label create "$label" --force
done
gh label create 'autorelease: pending' --color ededed \
  --description 'Generated release PR awaiting maintainer approval' --force
```

Prepare Release refuses to run without `autorelease: pending`, because a
release PR that does not carry it can never be published by **Release**.

Allow Actions to open the release pull request. Without this, `GITHUB_TOKEN`
may push a branch but not open a PR, and `gh pr create` fails:

```sh
gh api --method PUT "repos/${OWNER}/${REPO}/actions/permissions/workflow" \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true
```

Keep `default_workflow_permissions` at `read`: every workflow here declares its
own `permissions:` block. The same flag also permits Actions to approve pull
requests, so protecting `main` is what keeps a release PR from being approved
by automation.

## Maintainer checks

Keep actions and Kind pinned, protect `main`, require **PR Release Metadata**,
and run `sh scripts/release-contract-check.sh` for release automation changes.

## Artifact Hub

[Artifact Hub](https://artifacthub.io) is where most Helm users discover
charts. The chart is prepared for it: `Chart.yaml` carries the
`artifacthub.io/*` annotations that populate the listing,
`artifacthub-repo.yml` is the ownership file used to claim the repository and
become a Verified Publisher, and releases are signed with cosign, which
Artifact Hub detects and displays. Registration is a one-time manual step
that needs a maintainer's Artifact Hub account.

### One-time setup

1. **Sign in** at <https://artifacthub.io> (GitHub sign-in works).

2. **Add the repository** under *Control Panel → Repositories → Add*:
   - **Kind:** `Helm charts`
   - **Name:** `kube-oidc-proxy` (this becomes the URL slug)
   - **URL:** `oci://ghcr.io/rafpe/charts/kube-oidc-proxy`

3. **Copy the Repository ID** shown for the new repository and paste it into
   `chart/kube-oidc-proxy/artifacthub-repo.yml` (replacing the placeholder).
   Commit that change.

4. **Publish the ownership metadata** to the OCI registry once, so Artifact Hub
   can verify you own it (requires [`oras`](https://oras.land) and a GHCR login):

   ```bash
   echo "$GITHUB_TOKEN" | oras login ghcr.io -u <your-github-user> --password-stdin

   oras push ghcr.io/rafpe/charts/kube-oidc-proxy:artifacthub.io \
     --config /dev/null:application/vnd.cncf.artifacthub.config.v1+yaml \
     chart/kube-oidc-proxy/artifacthub-repo.yml:application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml
   ```

Artifact Hub re-indexes the repository within a few minutes and shows the
chart, its annotations, and a "Verified Publisher" badge.

### Keeping the listing fresh

Nothing extra is needed per release. Artifact Hub polls the OCI repository and
picks up new chart versions automatically. The `artifacthub.io/*` annotations in
`Chart.yaml` travel with each packaged chart. The release automation
(`.github/workflows/release-image.yaml`) already pins the `artifacthub.io/images`
tag to the released version, so the listing always advertises the matching image.
