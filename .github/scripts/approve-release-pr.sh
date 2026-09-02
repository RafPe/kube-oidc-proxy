#!/usr/bin/env bash
# Approve a release PR with a status-card review body. Both approval paths in
# claude-review.yaml call this, so every path enforces the same guards:
#   - refuse PRs that are not the release automation's own same-repo
#     release/next branch
#   - refuse when the diff carries anything beyond generated release files
#   - skip when a current approval already stands (idempotent across triggers)
set -euo pipefail

pr="${1:?usage: approve-release-pr.sh <pr-number>}"

# A failed gh call aborts via set -e, so every guard below runs on data that
# was actually fetched — never on an empty string from a swallowed error.
meta=$(gh pr view "${pr}" -R "${GITHUB_REPOSITORY}" \
  --json title,headRefName,headRefOid,isCrossRepository,latestReviews)
title=$(jq -r '.title' <<<"${meta}")
head_ref=$(jq -r '.headRefName' <<<"${meta}")
head_sha=$(jq -r '.headRefOid[0:7]' <<<"${meta}")
cross=$(jq -r '.isCrossRepository' <<<"${meta}")

# Only the release automation's own branch qualifies, whatever labels a PR
# carries and whichever workflow path called us.
if [ "${cross}" != "false" ] || [ "${head_ref}" != "release/next" ]; then
  echo "::error::PR #${pr} head is ${head_ref} (cross-repo: ${cross}), not this repo's release/next — refusing to auto-approve"
  exit 1
fi

# Release PRs may only carry content Prepare Release generated; anything else
# means release/next was pushed to outside the release tooling and needs a
# human review instead of an auto-approval. Runs before the already-approved
# short-circuit so a tampered push is flagged on every trigger, independent of
# the ruleset's dismiss-stale-reviews setting.
diff_files=$(gh pr diff "${pr}" -R "${GITHUB_REPOSITORY}" --name-only)
if [ -z "${diff_files}" ]; then
  echo "::error::could not resolve any changed files for release PR #${pr} — refusing to auto-approve"
  exit 1
fi
unexpected=$(grep -Ev '^(CHANGELOG\.md$|\.changes/)' <<<"${diff_files}" || true)
if [ -n "${unexpected}" ]; then
  echo "::error::release PR #${pr} touches files outside CHANGELOG.md/.changes/ — refusing to auto-approve"
  printf '%s\n' "${unexpected}"
  exit 1
fi

# latestReviews holds each reviewer's current review, so a standing approval
# means nothing to do; a push dismisses it (DISMISSED, dismiss-stale is on in
# the main ruleset) and the next trigger re-approves.
approved=$(jq '[.latestReviews[] | select(.state == "APPROVED")] | length' <<<"${meta}")
if [ "${approved}" -gt 0 ]; then
  echo "::notice::PR #${pr} already has a current approval"
  exit 0
fi

version="${title#chore: release }"
run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"

body=$(mktemp)
cat >"${body}" <<EOF
## ✅ Release PR — auto-approved

|             |   |
| ----------- | - |
| **Verdict** | Approved without review (release gate) |
| **Release** | \`${version}\` |
| **Why**     | Diff verified to carry only generated \`CHANGELOG.md\` + \`.changes/\` fragment changes |
| **Head**    | \`${head_ref}\` @ \`${head_sha}\` — a force-push dismisses this approval and the next trigger re-approves |
| **Trigger** | [${GITHUB_WORKFLOW} run](${run_url}) |

<sub>🤖 Policy: PRs labeled <code>autorelease:*</code> from <code>release/next</code> are approved automatically — <code>.github/workflows/claude-review.yaml</code></sub>
EOF
gh pr review "${pr}" -R "${GITHUB_REPOSITORY}" --approve --body-file "${body}"
