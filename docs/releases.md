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
credentials. A change that fixes a vulnerability uses kind `Security` and
names the advisory (`CVE-…`, `GHSA-…` or `GO-…`) in the body, so every
release's notes identify the vulnerabilities it fixes. The required **PR Release Metadata** check enforces the label and
fragment relationship. The generated release PR is narrowly exempt only when
its repository, branch, and `autorelease: pending` label all match.

## Cutting a release

1. Confirm all intended PR labels and fragments, then merge them.
2. Run **Actions -> Prepare Release -> Run workflow** on `main`:

   ```sh
   gh workflow run prepare-release.yml --ref main
   ```

3. Review the generated release PR's version, notes, and `CHANGELOG.md` section.
   The **release-readiness** check runs `make verify test` and the release
   metadata checks on that PR. Merge only when it is green.
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

If **Release** fails before the tag exists (`release:check` or `release:e2e`
failed on the merged release PR), the changelog entry and the draft release
already exist but nothing was tagged or published. Do not re-run the failed
`pull_request` run: it checks out the original merge commit, which still lacks
the fix. Instead:

1. Fix forward on `main` with a `release/skip` PR. Its own CI runs the unit
   tests, the release contract check, and the E2E suite against the fix.
2. Tag the fixed `main` commit by hand and push the tag. The tag push triggers
   **release-image**, which builds, signs, and publishes the image and chart:

   ```sh
   git fetch origin
   git tag -a vX.Y.Z -m "Release vX.Y.Z" origin/main
   git push origin refs/tags/vX.Y.Z
   ```

3. When **release-image** is green, promote the draft that **Prepare Release**
   created: `gh release edit vX.Y.Z --draft=false`.

Do not also dispatch **Release** with that tag: its `release:artifact` job
would publish the image and chart a second time.

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

Create the CI and review labels. `ci/e2e` starts the end-to-end workflows on
a PR, and `review/claude-allowed` allows the Claude review. See
[CI labels](./development.md#ci-labels) and
[Claude review](./development.md#claude-review).

```sh
gh label create ci/e2e --color 1d76db --description 'Run the e2e workflows on this PR' --force
gh label create review/claude-allowed --description 'Allow the Claude review on this PR' --force
```

Branch protection on `main` requires these status checks: `test:unit`,
`lint:go`, `scan:vuln`, `scan:codeql`, `gate:e2e` and `gate:e2e-oidc`. The two
`gate:*` contexts are commit statuses that the e2e workflows set, not job
names.

The workflows read these repository secrets:

| Secret | Used by |
| --- | --- |
| `RELEASE_APPROVE_PAT` | The approval of the release PR. See [Release PR](./development.md#release-pr). |
| `ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID`, `ANTHROPIC_SERVICE_ACCOUNT_ID`, `ANTHROPIC_WORKSPACE_ID` | The Claude review with workload identity federation. |
| `CLAUDE_CODE_OAUTH_TOKEN` | The Claude review with `CLAUDE_REVIEW_AUTH=token`. |

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

## Website

The site at <https://rafpe.github.io/kube-oidc-proxy/> is built by the
**pages** workflow from `website/` (Astro Starlight) with the markdown under
`docs/` staged in by `website/site.manifest.json`; the manifest is the only
place a page is added to the navigation, and a doc that is not listed there
fails the build. Pull requests build the site and upload it as a `site`
workflow artifact; pushes to `main` deploy it.

### Documentation versions

The header version selector lists development documentation and the three newest stable releases with documentation.
Select **All versions** to show the full archive. Select **Recent versions** to restore the short list.
Older versions keep their direct URLs. When you open one, the selector identifies it as an archived version.
Each tagged site builds from its own checkout and package lock.
The archive starts with `v1.9.0`. Earlier tags do not contain the website.

The workflow includes all eligible tagged sites in each Pages deployment.
For example, `v2.1.0` lives under `/kube-oidc-proxy/v2.1.0/`.
The root path serves the current checkout. The build uses the configured base path for custom domains.

Switching versions preserves the current page when that version contains it.
Otherwise, the selector opens that version's Getting Started page.
Older versions do not receive newer explanations or interactive pages.
Only their version navigation uses the current selector.

A failed archive build fails the deployment. The selector lists only archives included in the completed build.
Tag contents stay fixed, but this process rebuilds the HTML. It does not retain byte-identical copies of previous deployments.

To preview the complete archive, run these commands from `website/`:

```sh
npm run build
npm run archive
npm run preview -- --host 127.0.0.1 --port 4321
```

The archive command needs local release tags and network access for locked npm dependencies.
A regular `npm run build` creates only the current site. Run `npm run archive` again to restore local version choices.

### Repository settings

Two repository settings are not in this repository and must be in place
before the first pull request that touches the site merges: without Pages
enabled, `actions/configure-pages` fails the build job on every such PR.

```sh
# Publish from the workflow rather than from a branch.
gh api --method POST "repos/${OWNER}/${REPO}/pages" -f build_type=workflow

# Only main may deploy through the github-pages environment.
gh api --method PUT "repos/${OWNER}/${REPO}/environments/github-pages" \
  --input - <<'JSON'
{ "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true } }
JSON
gh api --method POST "repos/${OWNER}/${REPO}/environments/github-pages/deployment-branch-policies" \
  -f name=main -f type=branch
```

A custom domain is configured in **Settings > Pages** only; the build takes
its base path from `actions/configure-pages`, so no code changes when the
domain changes. To preview locally, run `make site_dev`. Do not make
**site:build** a required check: the workflow is path-filtered, so a PR that
does not touch the site would wait on it forever.

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
