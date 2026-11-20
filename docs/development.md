# Development and testing

Building the proxy, running it against a local cluster, the end-to-end suite,
and a local multi-issuer test against a real GitHub Actions token. For running
the proxy in production see [operations](./operations.md).

- [Build and test](#build-and-test)
  - [Local dev cluster](#local-dev-cluster)
  - [End-to-end tests](#end-to-end-tests)
- [Local multi-issuer test: kind and GitHub Actions](#local-multi-issuer-test-kind-and-github-actions)
  - [Prerequisites](#prerequisites)
  - [1. Token-minting workflow (one-time)](#1-token-minting-workflow-one-time)
  - [2. Build the image and create the cluster](#2-build-the-image-and-create-the-cluster)
  - [3. Deploy the chart](#3-deploy-the-chart)
  - [4. RBAC](#4-rbac)
  - [5. Mint a token and fetch it (TTL ~5 min — move fast)](#5-mint-a-token-and-fetch-it-ttl-5-min--move-fast)
  - [6. Test through the proxy](#6-test-through-the-proxy)
  - [7. Access logs and cleanup](#7-access-logs-and-cleanup)
  - [Adding the next system](#adding-the-next-system)
- [Chart checks](#chart-checks)
- [Log contract](#log-contract)
- [Architecture diagrams](#architecture-diagrams)
- [See also](#see-also)

## Build and test

Building `kube-oidc-proxy` requires Go 1.26 or higher.

### Local dev cluster

A few `make` targets spin up a kind cluster for quick testing:

- `make dev_cluster_create` — create a kind cluster and build/load the proxy and
  tooling images onto each node.
- `make dev_cluster_deploy` — build, load, and deploy the proxy alongside a fake
  OIDC issuer, reachable via a NodePort service. It prints a signed OIDC token
  valid for the proxy, which you can use directly:

  ```bash
  curl -k https://<node-ip>:<nodeport> -H 'Authorization: bearer <token>'
  ```

  Set `KUBE_OIDC_PROXY_FAKE_APISERVER=true make dev_cluster_deploy` to also
  deploy a fake API server that logs the headers and request body the proxy
  sends — useful for inspecting impersonation output.
- `make dev_cluster_destroy` — delete the test cluster.

### End-to-end tests

`make e2e` runs the Go end-to-end suite (`test/e2e/suite`) against a real
Kubernetes cluster. It's hermetic: it builds the proxy and test-tool images from
source, creates its own [kind](https://kind.sigs.k8s.io) cluster, loads the
images, runs the suite, and tears the cluster down on exit (including on failure
or interrupt). No pre-existing cluster is required.

Prerequisites (all on `PATH`): `go`, `docker` (daemon running), `kind`,
`kubectl`, `helm`. Images are built for the host architecture, so the suite runs
on both `amd64` and `arm64` (e.g. Apple Silicon). The suite deploys the proxy
with the ClusterRole rendered from the Helm chart, not a copy of its own, so a
permission the proxy needs but the chart does not grant fails the suite; a unit
test in the framework checks the same thing against the list of extra keys the
proxy code emits.

```sh
make e2e          # build images, spin up kind, run the suite, tear down
make e2e-clean    # delete a leftover e2e kind cluster (safe if none exists)
```

Useful overrides: `E2E_TIMEOUT` (Go test timeout, default `30m`) and
`KUBE_OIDC_PROXY_K8S_VERSION`, which selects among the versions declared in
`test/e2e/versions/kubernetes-versions.json` (default: the newest). Versions
outside the manifest are refused — the manifest is the definition of what
this commit supports. CI tests the full declared window on a pull request,
on the twice-daily scheduled run and on a manual run. The Release workflow
tests the newest declared version.

The suite runs in CI (`.github/workflows/e2e.yaml`) on a pull request with the
label `ci/e2e`, on the twice-daily schedule and in the Release workflow. See
[CI labels](#ci-labels). A companion workflow
(`.github/workflows/e2e-oidc-gha.yaml`) proves the multi-issuer router
against the **real** GitHub Actions OIDC issuer alongside a local
Dex issuer. It runs `hack/ci/gha-multi-issuer-e2e.sh` in two jobs:

- `test:e2e-oidc` uses the upstream kind, with one GitHub Actions issuer.
- `test:e2e-oidc-shared-issuer` uses the proxy kind, with three issuers on
  the GitHub Actions issuer URL (ADR-0001). The job mints a real token for
  each audience and checks three results. Each token maps to the username
  of its own issuer. A token for the audience of `gha-foreign`, which pins
  another owner, gets `401`.
  The proxy refuses an unknown audience with `401` and
  `reason=audience_unrouted`.

To run the proxy-kind job locally without a GitHub token, set
`GHA_CONFIG_KIND=proxy`. Only the local Dex checks then run.

For a scripted multi-issuer demo, see [`../demo/README.md`](../demo/README.md).

## Local multi-issuer test: kind and GitHub Actions

This runs the proxy in a local [kind](https://kind.sigs.k8s.io/) cluster and
authenticates with a **real GitHub Actions OIDC token**. GitHub only mints these
tokens inside a workflow run, so the flow is:

![GitHub Actions mints a short-lived ID token; the local terminal downloads it and calls kubectl with it against kube-oidc-proxy in kind, which verifies the JWT via token.actions.githubusercontent.com and impersonates the mapped identity to the kind API server, where RBAC decides](./diagrams/gha-token-flow.svg)

<!-- Source: ./diagrams/gha-token-flow.archify.json; see docs/development.md, Architecture diagrams. -->

### Prerequisites

- `docker`, `kind`, `helm`, `kubectl`, `gh` (authenticated: `gh auth status`).
- Set these once per shell — every `gh` call needs an explicit `--repo`:

```bash
export GH_SLUG="rafpe/kube-oidc-proxy"   # <owner>/<repo> hosting the mint workflow
export BRANCH="master"
```

### 1. Token-minting workflow (one-time)

You need a `workflow_dispatch` workflow in the repository that requests an ID
token (`permissions: id-token: write`, then `core.getIDToken(<audience>)`)
and uploads it as a short-lived artifact.

> [!NOTE]
> This repository's own [`.github/workflows/oidc.yaml`](../.github/workflows/oidc.yaml)
> is a minimal example to copy from. The audience it requests
> (`kube-oidc-proxy-kind-test`) is the one the proxy config in step 3 expects;
> the two must match.

> [!WARNING]
> The artifact briefly holds a live token. It expires after ~5 minutes and only
> grants what your **local test cluster's** RBAC allows, but treat it as a
> secret all the same.

### 2. Build the image and create the cluster

```bash
docker build -t kube-oidc-proxy:test .
kind create cluster --name oidc-test
kind load docker-image kube-oidc-proxy:test --name oidc-test
```

### 3. Deploy the chart

This uses the simple `sub`-as-username mapping, which is enough to prove the
flow. The mapping to run in production, with a stable username, trust tiers,
audit extras and numeric-ID pinning, is the
[GitHub Actions recipe](./integrations.md#github-actions).

```bash
cat > /tmp/values-test.yaml <<'EOF'
image:
  repository: kube-oidc-proxy
  tag: test
  pullPolicy: Never

authenticationConfig:
  content: |
    apiVersion: apiserver.config.k8s.io/v1
    kind: AuthenticationConfiguration
    jwt:
    - issuer:
        url: https://token.actions.githubusercontent.com
        audiences: ["kube-oidc-proxy-kind-test"]
      claimMappings:
        # GitHub's newer sub is ID-embedded: repo:Owner@<owner_id>/repo@<repo_id>:ref:...
        username:
          claim: sub
          prefix: "gha:"
        # GitHub tokens carry no groups claim — CEL synthesizes one from
        # repository_owner (case-sensitive: "RafPe" != "rafpe"):
        groups:
          expression: '["github:" + claims.repository_owner]'
EOF

helm install kube-oidc-proxy oci://ghcr.io/rafpe/charts/kube-oidc-proxy \
  -n kube-oidc-proxy --create-namespace -f /tmp/values-test.yaml
kubectl -n kube-oidc-proxy rollout status deploy/kube-oidc-proxy --timeout=180s

# The proxy lists its issuers at startup, then reports each one initialized:
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy \
  | jq -r 'select((.event_type // "") | startswith("oidc.issuer.")) | [.event_type, .issuer_name] | @tsv'
```

To change config later, edit the values file and `helm upgrade kube-oidc-proxy
./chart/kube-oidc-proxy -n kube-oidc-proxy -f /tmp/values-test.yaml` — the
checksum annotation rolls the pods automatically.

### 4. RBAC

Decode a token first (step 5) if you're unsure of your exact claims. With the
default `sub` mapping and GitHub's ID-embedded subject format:

```bash
# Group binding — matches the CEL-synthesized group (mind the case!):
kubectl create clusterrolebinding gha-owner-view \
  --clusterrole=view --group="github:RafPe"

# Exact-subject binding — GitHub's sub embeds owner/repo IDs:
kubectl create clusterrolebinding gha-branch-view \
  --clusterrole=view \
  --user="gha:repo:RafPe@9809655/kube-oidc-proxy@1308696420:ref:refs/heads/master"
```

### 5. Mint a token and fetch it (TTL ~5 min — move fast)

```bash
gh workflow run oidc.yaml --repo "$GH_SLUG" --ref "$BRANCH"
sleep 5
RUN_ID=$(gh run list --repo "$GH_SLUG" --workflow=oidc.yaml -L1 \
  --json databaseId -q '.[0].databaseId')
gh run watch "$RUN_ID" --repo "$GH_SLUG"
rm -rf /tmp/oidc && gh run download "$RUN_ID" --repo "$GH_SLUG" \
  -n oidc-token -D /tmp/oidc
TOKEN=$(cat /tmp/oidc/token.jwt)

# Inspect the claims you are about to authenticate with:
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null \
  | jq '{iss,aud,sub,repository,repository_owner,ref}'
```

### 6. Test through the proxy

```bash
kubectl -n kube-oidc-proxy port-forward svc/kube-oidc-proxy 8443:443 &
sleep 3
```

Who does the cluster think you are?

```bash
kubectl --server=https://127.0.0.1:8443 --insecure-skip-tls-verify=true \
  --token="$TOKEN" auth whoami
```

Expected: your prefixed username plus groups `[github:RafPe, system:authenticated]`.
Then prove authorization scoping:

```bash
PROXY="--server=https://127.0.0.1:8443 --insecure-skip-tls-verify=true --token=$TOKEN"
kubectl $PROXY get pods -A        # allowed  (view)
kubectl $PROXY create ns nope     # forbidden (view cannot write)
```

If you get `401`, the token expired — rerun step 5. Steps 2–4 stay up.

> `--insecure-skip-tls-verify` is acceptable only against this throwaway kind
> cluster (the chart generated an ephemeral self-signed cert). Real deployments
> set `tls.secretName`/cert-manager and ship the CA in kubeconfig.

### 7. Access logs and cleanup

```bash
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy --tail=20   # request.access.decided: AuSuccess / AuFail
kill %1
kind delete cluster --name oidc-test
```

### Adding the next system

A pure config change — no new deployments:

1. Append another `jwt:` entry to `authenticationConfig.content` (its issuer
   URL, its own audience, and a **distinct prefix**, e.g. `sys-a:` — never reuse
   or omit prefixes across issuers).
2. Add RBAC bindings for the new prefixed identities.
3. `helm upgrade` — pods roll automatically; with the default readiness mode the
   rollout completes even if the new issuer is temporarily unreachable (it's
   logged as pending and starts working the moment its JWKS loads).

## Chart checks

Committed fixtures under `chart/kube-oidc-proxy/ci/` cover both authentication
configurations and are used by the `helm-chart` GitHub Actions workflow,
together with two scripts that pin down what the chart renders:

```sh
helm lint chart/kube-oidc-proxy -f chart/kube-oidc-proxy/ci/single-issuer-values.yaml
helm template t chart/kube-oidc-proxy -f chart/kube-oidc-proxy/ci/multi-issuer-values.yaml
bash hack/verify-chart-logging.sh   # logging values render as flags
bash hack/verify-chart-rbac.sh      # ClusterRole grants every declared userextras key
bash hack/verify-chart-metrics.sh   # metrics values render the listener, Service and monitors
```

## Log contract

The event registry in [`pkg/logging/events.go`](../pkg/logging/events.go) is
the source for the [event table](./logging.md#event-registry) in the logging
reference; `make eventdoc` regenerates it and CI fails on a diff. Never
hand-edit between the `events:begin` and `events:end` markers. The rules that
keep saved queries working across releases are in
[logging: compatibility](./logging.md#compatibility).

## Architecture diagrams

The C4 diagrams under [`docs/c4/`](./c4/) are generated from
[`workspace.dsl`](./c4/workspace.dsl) with Structurizr; edit the DSL, not the
PNGs. [Architecture](./architecture.md#diagrams) shows them.

`docs/diagrams/*.svg` and `demo/diagrams/*.svg` are checked by
`hack/verify-diagrams.sh` in CI. Two kinds exist:

- Hand-authored SVGs (`metrics-data-flow.svg`): literal colours, a `<title>`,
  no CSS variables.
- Archify exports (`gha-token-flow.svg`, `demo/diagrams/multi-issuer-demo.svg`):
  built from the `*.archify.json` next to each SVG with Archify 3.0.1, a
  local tool that is not a dependency of this repository (it ships as the
  `archify` agent skill; its CLI is `node <skill-dir>/bin/archify.mjs`). To
  change one, edit the JSON, run
  `archify finalize architecture <name>.archify.json <name>.html`, then
  `node website/scripts/export-diagram-svg.mjs <name>.html <name>.svg` from
  `website/` after `npm ci`. Use the same Archify version so the output only
  changes where the JSON did. The export follows the reader's colour scheme
  and embeds its fonts.

## Metrics demo

`hack/metrics-demo/` builds a kind cluster running kube-prometheus-stack and
this chart with metrics, a ServiceMonitor and the three Grafana dashboards, and
proves the dashboards are honest: it drives nineteen kinds of traffic —
allowed and forbidden requests, a 5xx the API server itself answers, invalid,
expired and username-less tokens, allowed, denied and simultaneous
impersonation, the two anomaly denials, both token-passthrough outcomes, a
watch, an exec, a log stream, non-resource paths and nine non-Kubernetes verbs
— fails if any dashboard panel's query returns an empty result, and only then
captures the screenshots in `docs/dashboards/`. It fakes no failure of the hop
to the API server, so the overview's "Upstream failures/s" panel reads zero, as
it should against a healthy upstream. Four steps, each one command:

```sh
make metrics_demo_up                                     # cluster, Prometheus, Grafana, the chart
make metrics_demo_load METRICS_DEMO_LOAD_ARGS=--once     # one call of every traffic kind
make metrics_demo_load METRICS_DEMO_LOAD_ARGS="--duration 10m"
make metrics_demo_verify                                 # every panel has data; write the PNGs
make metrics_demo_down                                   # delete the cluster and its state
```

`up` leaves `hack/metrics-demo/.state/` holding the kubeconfig, the mock
issuer's CA, key and URL and the proxy's serving certificate; the load
generator and `verify` read it, and `down` removes it. It needs Docker, Go,
kubectl, helm, jq and curl — but no `kind` CLI: the scripts run the kind pinned
in `go.mod`, which is the one the e2e suite uses. Prerequisites, the pinned
versions and what each file does are in
[`hack/metrics-demo/README.md`](../hack/metrics-demo/README.md).

## Interactive documentation

The [request flow](./interactive/request-flow.md) and [identity explorer](./interactive/identity-and-rbac.md) use Astro components in `website/src/components/interactive/`.
Edit their explanations in `request-content.cjs` and the corresponding Markdown pages.
The build checks that each request stage references a unique Go function anchor.
It excludes these references and Go source from the browser data.
Update the anchors when a function moves or changes its signature.
The explorer uses the same checkout as the documentation.
A clean tagged checkout displays the release version. Local changes display Development in the version selector.

Run these commands from `website/`:

```sh
npm ci
npm test
npm run build
npm run check
npm run preview -- --host 127.0.0.1 --port 4321
```

Open `http://127.0.0.1:4321/kube-oidc-proxy/interactive/request-flow/`.
For browser checks, set `CHROME_PATH` to a local Chromium executable and run `node scripts/interactive-browser.mjs`.
These checks cover request scenarios, controls, identity rules, and narrow screens.

## CI labels

The end-to-end workflows run on a pull request only after a collaborator adds
the label `ci/e2e`. Unit tests, lint and the scans run on every push.

| Label | What it starts |
| --- | --- |
| `ci/e2e` | `e2e.yaml` (`test:e2e`, all supported Kubernetes versions) and `e2e-oidc-gha.yaml` (`test:e2e-oidc`, `test:e2e-oidc-shared-issuer`) |

1. Open the PR. The commit statuses `gate:e2e` and `gate:e2e-oidc` show
   pending, with the text "waiting for label ci/e2e". The e2e jobs show as
   skipped.
2. Add the label `ci/e2e` when the PR is ready to test. Both workflows start.
3. Each later push runs both workflows again. A newer push cancels the run of
   an older push.
4. Each workflow sets its gate status to success or failure from its result.

Branch protection on `main` requires `gate:e2e` and `gate:e2e-oidc`, not the
names of the e2e jobs. GitHub counts a skipped job as passed, so a required
job name would let a PR without the label merge without e2e. A pending
status blocks the merge, and it shows yellow, not red.

Other rules:

- A label other than `ci/e2e` does not start e2e, and it does not cancel a
  running e2e.
- A release PR (label `autorelease`) runs e2e without the label.
- A Dependabot PR needs the label, as every other PR does.
- A push to `main` runs `e2e-oidc-gha.yaml`, because a real GitHub Actions
  token has different claims on a push. The schedule and the Release
  workflow run `e2e.yaml`.
- A PR from a fork gets a read-only token and cannot set the gate statuses.
  To accept one, a maintainer pushes its commits to a branch in this
  repository and adds `ci/e2e` there. The maintainer then merges the fork PR
  with an admin bypass.

## Claude review

`.github/workflows/claude-review.yaml` runs an automated review of a pull request. The repository owner starts it with a PR comment `@claude review`.

### Start a review

1. Add the label `review/claude-allowed` to the PR.
2. Comment `@claude review` on the PR.

Without the label, the review does not start, and the workflow replies with a comment that asks for the label. A release PR is the exception. See [Release PR](#release-pr). The review runs only for comments of the repository owner. A PR from a fork gets a review, but never an automatic approval.

### What the jobs do

| Job | Purpose |
| --- | --- |
| `review:claude` | Reads the PR diff and posts the findings and one summary comment. Its GitHub token can only read. |
| `review:approve` | Approves the reviewed head commit when the review verdict is approve. A new push dismisses that approval. |
| `review:report` | Hides the review comments of earlier runs. Posts a notice when a run ends without a summary. |
| `review:label-missing` | Asks for the label `review/claude-allowed`. |
| `review:release-approve` | Approves the release PR of Prepare Release. See [Release PR](#release-pr). |

A re-review of the same PR reads the previous summary and the change since the reviewed head commit. It marks each earlier finding as fixed or open.

### Hidden comments

`review:report` hides these as outdated, so the PR shows only the latest review:

- each summary of the review except the newest one.
- each other comment of the review from before the current `@claude review`, when the current run posted a summary.
- each notice of `review:report` and `review:label-missing`.
- each `@claude review` comment of the owner except the current one.
- each approval of `review:approve` that GitHub dismissed after a new push.

A hidden comment stays in the GitHub API, so the next re-review still finds the previous summary. Select **Show comment** on GitHub to read a hidden comment.

### Release PR

A release PR is the PR `release/next -> main` that Prepare Release opens with an `autorelease` label. The review does not run on it, and it needs no `review/claude-allowed` label. Two paths approve it with the token in the secret `RELEASE_APPROVE_PAT`, because `github-actions[bot]` opens the PR and cannot approve its own PR:

- `review:release-approve` runs when the PR opens or gets a label, and when Prepare Release completes.
- `review:claude` approves it without a review when the owner comments `@claude review` on it.

Both paths run `.github/scripts/approve-release-pr.sh`. The script refuses a PR whose head is not `release/next` of this repository, and a PR that changes files outside `CHANGELOG.md` and `.changes/`. It does nothing when a current approval exists. `review:report` and its hide step do not run on a release PR. The merge of the release PR stays the human approval to publish, as [releases](./releases.md#cutting-a-release) describes.

### Credential

The repository variable `CLAUDE_REVIEW_AUTH` selects the credential of the review:

| Value | Credential | Secrets |
| --- | --- | --- |
| `wif`, or the variable is not set | Workload identity federation | `ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID`. Optional: `ANTHROPIC_SERVICE_ACCOUNT_ID`, `ANTHROPIC_WORKSPACE_ID`. |
| `token` | OAuth token | `CLAUDE_CODE_OAUTH_TOKEN` |

The value is not case-sensitive. The job stops before the review for any other value, or when a required secret is empty. The `token` mode puts a long-lived token in a job that reads untrusted PR content. Use it only for a short time.

```sh
gh variable set CLAUDE_REVIEW_AUTH --body token
gh variable set CLAUDE_REVIEW_AUTH --body wif
```

## See also

- [Operations](./operations.md) — running the proxy in production.
- [Releases](./releases.md) — how a merged change becomes a release.
- [Multi-issuer authentication](./multi-issuer.md) — the configuration the
  local test exercises.
