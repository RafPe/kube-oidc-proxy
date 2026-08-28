# Maintaining this fork

`github.com/rafpe/kube-oidc-proxy` is an independent fork. This document
describes how the fork stays secure on its own and how to pull fixes from
upstream when they are worth adopting.

## Independence model

The fork does not depend on any upstream project for its security posture. Its
own automation is the primary security channel:

- **`.github/dependabot.yml`** — weekly dependency update PRs for Go modules
  (`gomod`) and the GitHub Actions used by the workflows (`github-actions`).
- **`.github/workflows/security.yaml`** — runs `govulncheck ./...` on every
  pull request, on every push to `master`, and on a weekly schedule, so newly
  disclosed vulnerabilities are surfaced even without repository activity.

Treat a failing `security` workflow or an open Dependabot PR as the signal to
act; do not wait for an upstream release to address a vulnerability.

## Watching upstream

The active upstream for this codebase is
[`TremoloSecurity/kube-oidc-proxy`](https://github.com/TremoloSecurity/kube-oidc-proxy)
(the project originated at `jetstack/kube-oidc-proxy`, which is now archived).

To be notified of upstream changes:

- Watch the upstream repository's **Releases** (GitHub → Watch → Custom →
  Releases), or subscribe to its release Atom feed:
  `https://github.com/TremoloSecurity/kube-oidc-proxy/releases.atom`.
- Periodically review the upstream commit log and merged pull requests for
  security fixes and bug fixes that are relevant to the features this fork uses.

Adopt upstream changes selectively. Not every upstream change applies — this
fork carries its own module path, multi-issuer OIDC support, and independent
CI.

## Cherry-picking upstream changes

Use the existing helper `hack/cherry-pick-pull.sh` to bring an upstream pull
request onto a branch here.

```sh
# Prerequisites:
#   - the `hub` CLI (https://github.com/github/hub)
#   - GITHUB_USER exported (your user or org where your fork lives)
#   - an `upstream` remote pointing at the upstream repository, and an
#     `origin` remote pointing at this fork
export GITHUB_USER=<your-user>
git remote add upstream https://github.com/TremoloSecurity/kube-oidc-proxy.git   # once

# Cherry-pick PR 123 onto master and open a PR:
./hack/cherry-pick-pull.sh upstream/master 123

# Cherry-pick multiple PRs into a single proposal:
./hack/cherry-pick-pull.sh upstream/master 123 456

# Set DRY_RUN=1 to cherry-pick locally without pushing or opening a PR.
```

`UPSTREAM_REMOTE` (default `upstream`) and `FORK_REMOTE` (default `origin`)
override the remote names if yours differ.

### Reconciling the renamed import path

This fork renamed its Go module from `github.com/jetstack/kube-oidc-proxy` to
`github.com/rafpe/kube-oidc-proxy` (see the module rename commit). Upstream code
still uses the original import path, so cherry-picked changes that touch Go
imports will conflict or fail to build until the paths are reconciled. After a
cherry-pick:

```sh
# Rewrite any upstream import paths introduced by the cherry-pick.
grep -rl 'jetstack/kube-oidc-proxy' --include='*.go' . \
  | xargs sed -i '' 's#github.com/jetstack/kube-oidc-proxy#github.com/rafpe/kube-oidc-proxy#g'  # macOS; drop the '' on GNU sed

go build ./... && go vet ./... && go test ./...
```

Also note that `hack/cherry-pick-pull.sh` fetches the PR patch from a
hardcoded `github.com/jetstack/kube-oidc-proxy` URL. If you are cherry-picking
from `TremoloSecurity/kube-oidc-proxy`, fetch the patch from the correct
repository (for example
`https://github.com/TremoloSecurity/kube-oidc-proxy/pull/<n>.patch`) or update
that URL in the script before running it.

Do not rewrite the runtime impersonation extra keys
(`originaluser.jetstack.io-*`) — they are part of the impersonation API
contract and must stay as-is.

## Bumping the tested Kubernetes versions

The single source of truth is `test/e2e/versions/kubernetes-versions.json`:
the current Kubernetes minor plus the two before it, with node images copied
from one kind release. Everything else (the CI matrix, the kind CLI version
in CI, the default image of local `make e2e` runs) derives from it.

Two independent triggers, in the order they usually happen:

1. **A new Kubernetes minor goes GA.** Wait — do not edit anything yet. Node
   images only exist once a kind release ships them (kind picks the patch
   versions, we pick the minors).
2. **A kind release ships images for that minor** (watch
   https://github.com/kubernetes-sigs/kind/releases):
   - Update `.kind` and all three `supported` entries — versions and full
     `@sha256` digests copied verbatim from the release notes, newest first.
   - Bump the `k8s.io/*` modules in `go.mod` to the matching `v0.<minor>`.
     `go test ./test/e2e/versions/` fails until manifest and go.mod agree —
     that is the point: compatibility is verified, not assumed, before either
     lands alone.
   - Run the full matrix before merging: `gh workflow run e2e.yaml --ref <branch>`.
