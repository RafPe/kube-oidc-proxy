# Releases

Ordinary pull requests never publish a release. This repository uses the same
review-gated release contract as the other RafPe Go projects.

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

Keep actions and Kind pinned, protect `main`, require **PR Release Metadata**,
and run `sh scripts/release-contract-check.sh` for release automation changes.
