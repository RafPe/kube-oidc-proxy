# Proposal: make opt-in ServiceMonitor observability easy to enable and verify

Status: proposed. Research date: 2026-09-16. Baseline: `main` at `9eb81d82b`.
This proposal documents follow-up work; it does not change chart behavior.

## Recommendation

Use the chart's existing `metrics.serviceMonitor.enabled` boolean as the
ServiceMonitor toggle. Keep metrics collection opt-in through `metrics.enabled`.
Provide a short installation recipe and prove that Prometheus Operator discovers
and scrapes the target. Preserve both defaults as `false`.

The requested capability already exists. The remaining work is making it easy to
find, explaining the deployment-specific selection settings, and verifying the
complete monitoring path. Helm exposes values rather than a graphical button;
a consuming deployment UI can present these booleans as switches. Building a UI
or introducing a second `observability.enabled` API is outside this proposal.

## What exists today

| Surface | Current implementation |
| --- | --- |
| Metrics switch | `metrics.enabled` adds the listener argument, named container port and dedicated ClusterIP Service. |
| Monitor switch | `metrics.serviceMonitor.enabled` renders `monitoring.coreos.com/v1` ServiceMonitor; it errors if metrics are disabled. |
| Discovery | The monitor selects the metrics Service by application, release and component labels, in the application's namespace. Its endpoint references the Service port by name. |
| Integration controls | Monitor namespace, labels, annotations, intervals, relabeling and scrape limits are configurable. |
| Alternatives | PodMonitor is supported and mutually exclusive with ServiceMonitor. Dashboards and PrometheusRule have separate switches. |
| Exposure | The listener is HTTP without scrape authentication. The main proxy Service never receives the metrics port. Optional NetworkPolicy restricts metrics ingress. |
| Tests | Helm checks cover toggles, selectors, port naming, limits and conflicting options. Kind tests scrape through the Kubernetes Service proxy. |

Evidence: [values](../../chart/kube-oidc-proxy/values.yaml),
[ServiceMonitor template](../../chart/kube-oidc-proxy/templates/servicemonitor.yaml),
[metrics Service](../../chart/kube-oidc-proxy/templates/service-metrics.yaml),
[render checks](../../hack/verify-chart-metrics.sh), and
[current Kind metrics tests](../../test/e2e/suite/cases/metrics/metrics.go).
The metrics guide covers collectors, queries, dashboards and exposure, but lacks
a focused ServiceMonitor onboarding recipe. The Kind tests do not establish
Operator reconciliation or a successful scrape by a real Prometheus instance.

## User-facing configuration

Merge this snippet into the application's normal authentication values:

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    additionalLabels:
      release: monitoring
    interval: 30s
    scrapeTimeout: 10s
```

`monitoring` above is an example kube-prometheus-stack **Helm release name**, not
necessarily its namespace. Replace it with the label value selected by your
Prometheus resource. Custom installations may use a completely different label.
The intervals are example settings; leave them empty to inherit Prometheus defaults.

To stop Operator-managed scraping, set `metrics.serviceMonitor.enabled: false`.
The metrics listener stays enabled for another scraper. To turn off the endpoint
as well, set both booleans to `false` in the same upgrade. Changing the monitor
toggle alone must not alter the Deployment or restart application pods.

| `metrics.enabled` | `serviceMonitor.enabled` | Contract |
| --- | --- | --- |
| false | false | No listener, metrics Service or ServiceMonitor; no Operator dependency. |
| true | false | Listener and internal Service; usable by other monitoring systems. |
| true | true | Listener, internal Service and ServiceMonitor. |
| false | true | Clear Helm error explaining the missing prerequisite. |

## Discovery prerequisites

Prometheus Operator must already be running, the ServiceMonitor CRD installed,
and a Prometheus or PrometheusAgent resource configured to consume monitors.
The application chart should not install or own this shared monitoring stack.

There are three distinct selections:

1. Prometheus's `serviceMonitorNamespaceSelector` chooses namespaces containing
   monitors, and `serviceMonitorSelector` chooses monitor metadata labels.
2. The ServiceMonitor's `namespaceSelector` chooses the application's namespace;
   its `selector` chooses the dedicated metrics Service there.
3. The Service selects application pods; the monitor endpoint names the Service
   port, which routes to the named container port.

The [Operator design](https://prometheus-operator.dev/docs/getting-started/design/)
and [troubleshooting guide](https://prometheus-operator.dev/docs/platform/troubleshooting/)
explain these relationships. Setting `metrics.serviceMonitor.namespace` moves the
monitor object; it does not move the application Service. The destination
namespace must exist, the Operator must watch it, and Prometheus needs discovery
permissions in the application's namespace.

The upstream kube-prometheus-stack chart currently defaults
`serviceMonitorSelectorNilUsesHelmValues` to `true`: absent a custom selector, it
renders `release: <Helm release name>`. See its
[values](https://github.com/prometheus-community/helm-charts/blob/main/charts/kube-prometheus-stack/values.yaml)
and [Prometheus template](https://github.com/prometheus-community/helm-charts/blob/main/charts/kube-prometheus-stack/templates/prometheus/prometheus.yaml).
Document matching that selector, rather than recommending cluster-wide selection
of all monitors. Operators should inspect their actual Prometheus resource since
installed versions and overrides differ.

Keep explicit rendering when enabled. Do not gate it on
`.Capabilities.APIVersions.Has`: offline Helm and GitOps renders must retain the
requested object. Missing CRDs should produce an installation error, with the
prerequisite explained in the guide.

## Network access and ownership

Keep the existing dedicated ClusterIP Service and default `/metrics`, `http`,
`honorLabels: false` configuration. A ClusterIP is not an access-control boundary.
Use the existing `networkPolicy.metrics.from` peers to select the actual
Prometheus pods and namespace where policy enforcement is available. Account for
Prometheus egress policies too. A namespaceSelector and podSelector in the same
peer restrict access to their intersection; separate peers are alternatives. See
the [Kubernetes NetworkPolicy semantics](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

The guide should explain that this chart's NetworkPolicy defaults also admit
proxy and readiness traffic. Operators who already control those ports must
review `networkPolicy.additionalIngress` and the additive behavior of other
policies. See the existing [policy template](../../chart/kube-oidc-proxy/templates/networkpolicy.yaml)
and [exposure guidance](../metrics.md#exposure-and-hardening).

No new permissions belong on the proxy ServiceAccount. Monitoring discovery RBAC
belongs to Prometheus and the Operator. A loopback-only metrics bind address is
appropriate for a same-pod scraper, but cannot support direct ServiceMonitor
scraping. Setting `scheme: https` or `tlsConfig` does not add TLS to the current
HTTP listener. Listener TLS/authentication is separate future work.

## Alternatives considered

| Option | Tradeoff | Recommendation |
| --- | --- | --- |
| Existing two booleans with a short recipe | Preserves the distinction between exposing metrics and registering an Operator target. | Use this. Once metrics are on, ServiceMonitor is one toggle. |
| ServiceMonitor implicitly enables metrics | One switch from defaults, but changes today's error contract and makes exposure less explicit. | Keep explicit enablement. |
| New root `observability.enabled` switch | Convenient preset, but creates overlapping settings and precedence rules for monitors, dashboards and alerts. | Avoid a duplicate API. |
| Install kube-prometheus-stack as a dependency | Easier demo, but gives an application chart ownership of cluster-level monitoring. | Keep independently managed. |

## Proposed implementation PRs

1. **Onboarding and toggle contract.** Add a ServiceMonitor quick start to
   `docs/metrics.md`, link it from the chart README, and explain enable/disable
   behavior near the values. Provide same-namespace and cross-namespace examples
   and a selector troubleshooting sequence. Extend
   `hack/verify-chart-metrics.sh` to compare Deployment renders with the monitor
   on/off and explicitly cover custom monitor namespace and discovery labels.
   Retain existing compatibility checks instead of duplicating them.
2. **Operator integration test.** Add an isolated Kind scenario installing
   pinned Prometheus Operator CRDs/controller and Prometheus. Reuse the existing
   application deployment fixtures. Verify the rendered monitor is reconciled,
   the expected target is healthy, and `kube_oidc_proxy_build_info` is queryable.
   Use the Prometheus API, not just a direct request to `/metrics`. Include a
   cross-namespace case, a deliberately mismatched selector that yields no target,
   and toggling the monitor off then on. Set bounded polling and collect Operator
   logs, Prometheus target errors and relevant manifests on failure. Select and
   record tested dependency versions during implementation; pin clean full semver
   versions and keep this test isolated from existing fast metrics checks.

If a NetworkPolicy connectivity test is added, run it with a policy-enforcing
CNI; a default Kind network alone is not evidence that policy isolation works.
Do not expand the proxy RBAC, install a production monitoring stack, add alerts,
or alter metric families as part of these follow-ups.

## Acceptance criteria

- [ ] The documented recipe renders the intended monitor with the named metrics
  Service port, release-specific selector and application namespace.
- [ ] Default installation remains independent of Prometheus Operator CRDs.
- [ ] Monitor toggling changes discovery resources without changing the
  Deployment; disabling metrics removes its listener and Service.
- [ ] The guide distinguishes monitor metadata selection from Service selection
  and explains missing-CRD, no-target and target-down failures.
- [ ] Real Prometheus queries demonstrate healthy scrapes and build information
  for same-namespace and cross-namespace discovery.
- [ ] Existing Helm verification scripts pass; authentication, public Service
  ports and proxy RBAC remain unchanged.

## Proposal validation and release handling

Validation performed for this proposal:

- `bash hack/verify-chart-metrics.sh`: passed.
- `helm lint chart/kube-oidc-proxy -f chart/kube-oidc-proxy/ci/metrics-values.yaml`: passed.
- Rendered the YAML example with the single-issuer fixture and verified monitor
  namespace, selection label, application namespace, named port and interval.
- Checked relative link targets, `git diff --check`, and
  `sh scripts/release-contract-check.sh`: passed.

These checks do not demonstrate a live Operator scrape; that is the second
follow-up's acceptance gate. No live cluster was modified.

This documentation-only draft uses `release/skip` and adds no changelog fragment,
per the [release contract](../releases.md#contributor-metadata). Each subsequent
implementation PR must choose exactly one release label and include an unreleased
fragment whenever it is non-skip. No version bump or release is requested here.
