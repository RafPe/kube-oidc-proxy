#!/usr/bin/env bash
# Approve a release PR with a status-card review body. Both approval paths in
# claude-review.yaml call this, so every path enforces the same guards:
#   - skip when a current approval already stands (idempotent across triggers)
#   - refuse when the diff carries anything beyond generated release files
set -euo pipefail

pr="${1:?usage: approve-release-pr.sh <pr-number>}"

# latestReviews holds each reviewer's current review, so a standing approval
# means nothing to do; a push dismisses it (DISMISSED) and the next trigger
# re-approves.
approved=$(gh pr view "${pr}" -R "${GITHUB_REPOSITORY}" --json latestReviews \
  --jq '[.latestReviews[] | select(.state == "APPROVED")] | length')
if [ "${approved}" -gt 0 ]; then
  echo "::notice::PR #${pr} already has a current approval"
  exit 0
fi

# Release PRs may only carry content Prepare Release generated; anything else
# means release/next was pushed to outside the release tooling and needs a
# human review instead of an auto-approval.
unexpected=$(gh pr diff "${pr}" -R "${GITHUB_REPOSITORY}" --name-only \
  | grep -Ev '^(CHANGELOG\.md$|\.changes/)' || true)
if [ -n "${unexpected}" ]; then
  echo "::error::release PR #${pr} touches files outside CHANGELOG.md/.changes/ — refusing to auto-approve"
  printf '%s\n' "${unexpected}"
  exit 1
fi

meta=$(gh pr view "${pr}" -R "${GITHUB_REPOSITORY}" --json title,headRefName,headRefOid)
title=$(jq -r '.title' <<<"${meta}")
head_ref=$(jq -r '.headRefName' <<<"${meta}")
head_sha=$(jq -r '.headRefOid[0:7]' <<<"${meta}")
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
