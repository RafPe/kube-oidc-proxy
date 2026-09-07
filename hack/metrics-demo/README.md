# Metrics demo

A reproducible kind cluster that installs this chart with metrics, a
ServiceMonitor and the three Grafana dashboards, alongside
kube-prometheus-stack, drives the nineteen kinds of traffic listed under
[what the load generator drives](#what-the-load-generator-drives), proves every
dashboard panel returns data, and captures the screenshots in
[`docs/dashboards/`](../../docs/dashboards).

It is a demo, not a deployment reference: everything runs on one node, nothing
is hardened, and Grafana allows anonymous viewers so the screenshots can be
rendered without a login.

## Prerequisites

- **Docker**, running.
- **Go** (the version in `go.mod`). Go is what runs kind: the scripts invoke
  `go run sigs.k8s.io/kind`, the version pinned in `go.mod`, rather than the
  `kind` on `PATH`. A `kind` CLI older than the node image below fails with
  `your configuration file uses an old API spec: "kubeadm.k8s.io/v1beta3"`, so
  the demo deliberately does not use it. **You do not need a `kind` CLI.**
- **kubectl**, **helm**, **jq** and **yq** on `PATH`.
- **git**, and network access, for the kube-prometheus-stack chart, the
  container images, and the pinned Grafana dashboard linter that
  `hack/verify-chart-dashboards.sh` builds from a shallow clone (every
  published tag of it carries a `replace` directive, so
  `go run <module>@<version>` cannot build it).

## Pinned versions

Never "latest" — a demo that drifts is not reproducible, and the committed
screenshots were taken against exactly these.

| What | Version | Where |
| --- | --- | --- |
| kube-prometheus-stack chart | `89.2.2` | `KPS_VERSION` in `up.sh` |
| kind node image | `1.37.0`, digest-pinned | `NODE_VERSION` / `NODE_IMAGE_DIGEST` in `up.sh`, copied from `test/e2e/versions/kubernetes-versions.json` |
| kind | `0.33.0` | `sigs.k8s.io/kind` in `go.mod` |
| Grafana dashboard linter | `0.3.0` | `LINTER_VERSION` in `hack/verify-chart-dashboards.sh` |

## The four steps

| Command | What it does | What it leaves behind |
| --- | --- | --- |
| `make metrics_demo_up` | Creates the kind cluster `kube-oidc-proxy-metrics-demo`, builds and side-loads the proxy image under a tag carrying the build identity and the mock-issuer image, installs kube-prometheus-stack, deploys the issuer, installs this chart with `metrics.enabled`, `metrics.serviceMonitor.enabled` and `metrics.dashboards.enabled`, applies the demo RBAC and the `demo-shell` pod, then runs `check.sh`. | `.state/` with the kubeconfig, the issuer CA, key and URL, the proxy's serving certificate, and the image tag and version it deployed. |
| `make metrics_demo_load` | Runs the load generator. `METRICS_DEMO_LOAD_ARGS=--once` runs each traffic kind exactly once and fails if any call did not produce its expected status; `METRICS_DEMO_LOAD_ARGS="--duration 10m"` drives traffic for ten minutes. | One JSON log line per call on stdout. |
| `make metrics_demo_verify` | Queries every `expr` in every dashboard against the demo's Prometheus and fails if any returns an empty result, then renders each dashboard through Grafana's image renderer. | `docs/dashboards/overview.png`, `security.png`, `capacity.png`. |
| `make metrics_demo_down` | Deletes the cluster and `.state/`. | Nothing. |

`up.sh` is idempotent: re-running it after a failure resumes rather than
starting over. On the reference run it took about four minutes end to end.

## Why the proxy image tag is never the same twice

`helm upgrade --install` restarts pods only when something in the pod template
changes, and the image tag is the only part of it a rebuild moves. Side-load a
rebuilt image under a tag the pods already run and Helm sees nothing to do: the
previous build keeps serving, and the overview's Version panel reports a binary
that is not the one in the tree - the one panel an operator would trust to tell
them otherwise.

`hack/metrics-demo/imagetag.sh` derives the tag, and it is the only place that
does. From a clean tree it is the human-readable `demo-<version>`, the version
being the one `hack/lib/version.sh` stamps into the binary. From a dirty tree it
gains a short digest of the binary that was just built. The digest is of the
artifact, deliberately not of `git diff HEAD` and the untracked file list:
hashing the source would repeat across two rebuilds of an unchanged dirty tree
and put the bug straight back, while the binary carries a build date stamped to
the second, so every dirty rebuild gets its own tag and every dirty rebuild
rolls the pods.

`up.sh` derives it after `make build`, not before - the same ldflags are
expanded inside that recipe, and `make build` runs `generate` first - and writes
both values to `.state/image-tag` and `.state/image-version`. `check.sh` reads
them back rather than re-deriving anything, so a standalone run compares the
pods against what was actually deployed even if the tree has since moved on. It
asserts two things: every pod matching the chart's own selector runs exactly
that image (`demo-shell` and the issuer live in the same namespace and were
never meant to), and every pod's `kube_oidc_proxy_build_info` reports exactly
the version that was built. The equality subsumes the older "no `-dirty` from a
clean tree" check and closes the hole beside it, because both the tag and the
version now follow `git status` rather than `git describe --dirty`, which
ignores untracked files.

`hack/verify-demo-image-tag.sh` guards the derivation against a throwaway
repository - clean tag human-readable, two consecutive dirty builds at one HEAD
distinct, an untracked file enough to change the tag - and checks that nothing
else re-derives it. It needs no cluster and runs in CI.

## Why `check.sh` waits

Prometheus Operator discovery is asynchronous. `helm --wait` returns as soon as
the workloads are ready, but the operator still has to turn the chart's
ServiceMonitor into a scrape config and Prometheus has to reload it — about a
minute on the reference run. `check.sh` therefore polls
`up{job=~".*kube-oidc-proxy.*"}` for up to two minutes instead of asserting it
once, and prints a progress line every ten attempts.

## Why the demo mints its own serving certificate

The chart's self-generated TLS Secret cannot be verified from outside the
cluster: `secret_tls.yaml` signs the serving certificate with an ephemeral
`genCA` it never publishes, and emits no `subjectAltName`, so the `tls.crt` in
that Secret is a leaf nothing can build a chain to. The load generator reaches
the proxy through a port-forward on 127.0.0.1 and verifies it properly, so
`hack/metrics-demo/issuer` mints a certificate for the in-cluster Service name
plus 127.0.0.1 into Secret `kop-demo-tls`, `proxy-values.yaml` points the chart
at it with `tls.secretName`, and `.state/proxy-ca.pem` holds the issuing
certificate — the certificate only; the key stays in the Secret. Nothing in the
demo uses `InsecureSkipVerify`. Minting is idempotent: an existing Secret is
left alone, because replacing it would invalidate the `proxy-ca.pem` the demo
already trusts.

## Screenshots

`make metrics_demo_verify` writes `docs/dashboards/overview.png`,
`security.png` and `capacity.png`, each 1920x1800 - tall enough for all
four panel rows of every dashboard. It refuses to render them until every
`expr` in every dashboard returns a non-empty result against the demo's
Prometheus, so a screenshot of empty panels cannot be produced by accident,
and it rejects an image too small to be a populated dashboard. Run the load
generator for ten minutes first, or the panels have nothing to draw.

## What the load generator drives

The exact kinds, one per traffic shape the dashboards draw. `--once` runs each
one and asserts every call it makes; a scenario made of several calls asserts
and logs each of them separately.

| Kind | What it sends | What it is there for |
| --- | --- | --- |
| `allowed_list` | list pods with a valid token | 200 at namespace scope, `authn{oidc,accepted}`, `decisions{allow}` |
| `allowed_get` | get one pod | 200 at resource scope |
| `forbidden_by_rbac` | list nodes, which the demo identity is not granted | 403 from the API server after the proxy allowed the request |
| `upstream_5xx` | list pods at a resource version the API server will never observe | 504 from the API server, so the code-class panel has a 5xx band |
| `invalid_token` | a bearer that is not a JWT | 401, `decisions{deny,unauthorized}` |
| `expired_token` | a correctly signed token past its `exp` | 401 by a different route through the authenticator |
| `impersonation_allowed` | three identical `Impersonate-User: jjackson` calls | `review_requests{sar,allow}`, a cache miss then hits |
| `impersonation_coalesced` | eight identical impersonation calls at once, at one replica whose decision cache has just expired | that replica issues fewer SubjectAccessReviews than it answers calls |
| `impersonation_denied` | `Impersonate-User: mallory` | 403, `decisions{deny,impersonation_denied}` |
| `too_many_impersonation_values` | 100 `Impersonate-Group` headers | 431, refused on the header count before any review |
| `reserved_identity` | a token claiming `system:masters` | 403, `decisions{deny,reserved_identity}` |
| `no_username_claim` | a token the issuer signed that names nobody | 403, `decisions{deny,no_username_claim}`, asserted by counter delta |
| `passthrough_allowed` | three calls with the same ServiceAccount token | `authn{oidc,rejected}` then `{tokenreview,accepted}` |
| `passthrough_denied` | three calls with a well-formed token nobody vouches for | `authn{tokenreview,rejected}` |
| `watch` | a list-watch held open for 20s, then cancelled | `long_running_requests{watch}`, termination `client_cancel` |
| `exec` | `exec` into `demo-shell` | the hijack path: termination `hijacked`, code `none` |
| `logs` | read the pod's log | long-running but not hijacked |
| `non_resource` | `GET /version` and `GET /healthz`, both asserted | scope `none`, verb `get` |
| `hostile_methods` | nine methods `M1`..`M9`, each asserted | every one must project onto `k8s_verb="other"` |

**The demo's latency p99 is the `upstream_5xx` scenario, not proxy overhead.**
That scenario lists pods at a `resourceVersion` the API server will never
observe, and the API server takes about three seconds to give up and answer
504. The proxy forwards it and records the whole three seconds, so the
overview's p99 line sits near 3s: it is the proxy reporting a slow upstream
faithfully, which is what that panel is for. The scenario runs at most once
per rotation for exactly this reason.

**No upstream failure is faked.** `upstream_5xx` is a 5xx the API server itself
answers, so the proxy's exchange completes normally and its `termination` is
`normal`. Nothing in the demo makes the hop to the API server fail, so the
overview's "Upstream failures/s" panel reads a flat zero, which is the healthy
reading. That panel and four others fall back to `vector(0)` for exactly this
reason: a counter child that has never been incremented has no series at all,
and a panel that says "No data" where it should say zero is a panel an operator
learns to ignore. The two that group by a label write the fallback as
`or on() label_replace(vector(0), ...)`: `on()` keeps the zero out of the panel
once real series exist (a bare `or vector(0)` draws the unlabelled zero
*alongside* them, because an empty label set never matches a grouped one), and
the `label_replace` names it, so the legend reads `none` rather than a blank
row or Grafana's placeholder `Value`.

## What each file is

| File | Role |
| --- | --- |
| `up.sh` / `down.sh` | Build and tear down the demo. |
| `check.sh` | The state `up.sh` must leave behind; run on its own at any time. |
| `load.sh`, `load/` | The load generator; one traffic kind per metric family. |
| `verify.sh` | Panel-data proof and screenshot capture. |
| `kube-prometheus-stack-values.yaml` | Prometheus discovery, anonymous Grafana, the image renderer, the dashboard sidecar. |
| `proxy-values.yaml` | This chart, with metrics and dashboards on. |
| `demo-identities.yaml` | The RBAC the traffic kinds need to be allowed, and refused, plus the `demo-shell` pod. |
| `issuer/` | Deploys the e2e suite's mock OIDC issuer and writes its key material. |
