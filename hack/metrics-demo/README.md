# Metrics demo

A reproducible kind cluster that installs this chart with metrics, a
ServiceMonitor and the three Grafana dashboards, alongside
kube-prometheus-stack, generates every kind of traffic the metric catalogue
can observe, proves every dashboard panel returns data, and captures the
screenshots in [`docs/dashboards/`](../../docs/dashboards).

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
| `make metrics_demo_up` | Creates the kind cluster `kube-oidc-proxy-metrics-demo`, builds and side-loads the proxy and mock-issuer images, installs kube-prometheus-stack, deploys the issuer, installs this chart with `metrics.enabled`, `metrics.serviceMonitor.enabled` and `metrics.dashboards.enabled`, applies the demo RBAC and the `demo-shell` pod, then runs `check.sh`. | `.state/` with the kubeconfig, the issuer CA, key and URL, and the proxy's serving certificate. |
| `make metrics_demo_load` | Runs the load generator. `METRICS_DEMO_LOAD_ARGS=--once` runs each traffic kind exactly once and fails if any call did not produce its expected status; `METRICS_DEMO_LOAD_ARGS="--duration 10m"` drives traffic for ten minutes. | One JSON log line per call on stdout. |
| `make metrics_demo_verify` | Queries every `expr` in every dashboard against the demo's Prometheus and fails if any returns an empty result, then renders each dashboard through Grafana's image renderer. | `docs/dashboards/overview.png`, `security.png`, `capacity.png`. |
| `make metrics_demo_down` | Deletes the cluster and `.state/`. | Nothing. |

`up.sh` is idempotent: re-running it after a failure resumes rather than
starting over. On the reference run it took about four minutes end to end.

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
