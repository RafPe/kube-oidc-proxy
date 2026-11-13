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
  pull request, on every push to `main`, and on a weekly schedule, so newly
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
     lands alone. The same test fails if the `k8s.io` staging modules (every
     `k8s.io/*` module versioned `v0.<minor>.<patch>`, direct or indirect) are
     not all at one version; Dependabot's `kubernetes` group in
     `.github/dependabot.yml` proposes them as a single PR for that reason.
   - Run the full matrix before merging: `gh workflow run e2e.yaml --ref <branch>`.

## Test doubles

Two package suffixes, two meanings, each following the library it mirrors:

- **`fake`** (e.g. `pkg/authn/tokenreview/fake`,
  `pkg/authz/subjectaccessreview/fake`) holds an in-memory implementation of a
  client-go interface the parent package depends on, as client-go's own
  `kubernetes/fake` does. Use it where production code would take a real
  client.
- **`<pkg>test`** (e.g. `pkg/logging/logtest`, `pkg/metrics/metricstest`,
  `pkg/authn/authntest`) holds helpers for testing code that *uses* `<pkg>`:
  capture sinks, assertions and generated mocks, as `net/http/httptest` does
  for `net/http`.

A new double goes in whichever of the two matches what it stands in for; do
not add a third naming scheme. Helpers shared only by the e2e suite and the
metrics demo live under `test/util/`, one purpose-named package each
(`keybundle`, `idtoken`, `promtext`, `port`), never a catch-all `util`.

## Dependencies worth knowing about

**The apiserver library is the heaviest one, deliberately.** The proxy imports
`k8s.io/apiserver/pkg/server` and its options for secure serving with dynamic
certificate reload, the audit backends and policy, and CEL-based
authentication configuration. Those packages pull etcd, gRPC, OpenTelemetry
and cel-go into the binary even though no proxy code calls them directly.
Reimplementing the audit and serving pieces would cost more code than it
saves, so a Dependabot bump of one of those transitive trees is apiserver's
baggage, not a sign that the proxy started using it. Revisit only if upstream
splits audit and serving into a lighter module.

**The e2e harness shares the module.** `sigs.k8s.io/kind`, Ginkgo and Gomega
are direct requirements because `test/` and `hack/metrics-demo` live in the
same module; `go list -deps ./cmd` contains none of them, so they never reach
the binary. A separate test module with a `go.work` would shrink `go.sum` and
the govulncheck surface, at the cost of a more complicated `go test ./...` and
Makefile. Split only if that noise becomes a real maintenance cost.

