# ServiceMonitor toggle verification

The user requested implemented opt-in Helm ServiceMonitor observability.
The monitor already existed but required a second metrics switch. This change
makes the monitor switch enable its listener and Service automatically.

- RED: `bash hack/verify-chart-metrics.sh` failed with
  `metrics.serviceMonitor.enabled requires metrics.enabled` after adding the
  one-switch case (`82832e815`).
- GREEN: the same script passed with the shared enablement helper (`e5bdf621c`).
  A test assertion was corrected to compare namespace list length and element
  separately because yq does not compare arrays as expected with `==`.
- Coverage: one-switch and explicit two-switch renders are identical; default
  opt-out remains; optional metrics integrations render; listener validation
  still applies; custom monitor namespace/labels retain the application target;
  discovery-only changes preserve the Deployment with standalone metrics on.
- All six chart verifier scripts passed, along with Helm lint, ShellCheck and
  the release contract check. Existing single-issuer, multi-issuer and metrics
  fixture manifests match main byte-for-byte with a fixed serving TLS Secret.

The CI metrics fixture and local Prometheus demo use the one-switch setting.
No Go code changed. Helm template coverage is checked through rendered cases;
no line-coverage percentage is claimed.

Live validation: `bash hack/metrics-demo/up.sh` passed on an isolated Kind cluster
with the repository's pinned Kubernetes 1.37.0 and kube-prometheus-stack 89.2.2.
The demo values set only `metrics.serviceMonitor.enabled`, leaving
`metrics.enabled` false. The check queried Prometheus and confirmed `up=1` for
both ready proxy replicas, then verified each pod's build information. The run
ended with `metrics demo: ready`. Cross-namespace selection and discovery-only
Deployment stability are covered by rendered tests, not a live toggle test.
