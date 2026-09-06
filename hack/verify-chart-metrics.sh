#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# Metrics are opt-in. The default render must carry no metrics flag, port,
# Service or monitor: an image pinned to a release older than the one that
# added --metrics-bind-address must still get a command line it can parse
# (the same rule hack/verify-chart-logging.sh enforces for the logging
# flags). When enabled, the flag, the named container port and the dedicated
# Service must agree on the port, because the ServiceMonitor references the
# Service port by name.
CHART=chart/kube-oidc-proxy
BASE=(--set oidc.issuerUrl=https://x --set oidc.clientId=y)

render() { helm template kop "$CHART" "${BASE[@]}" "$@"; }

# 1. Default: nothing metrics-related renders.
out=$(render)
! grep -q -- '--metrics-bind-address' <<<"$out" || { echo "--metrics-bind-address rendered without metrics.enabled" >&2; exit 1; }
! grep -q 'name: kop-kube-oidc-proxy-metrics' <<<"$out" || { echo "metrics Service rendered without metrics.enabled" >&2; exit 1; }
! grep -q 'kind: ServiceMonitor' <<<"$out" || { echo "ServiceMonitor rendered without metrics.enabled" >&2; exit 1; }
! grep -q 'kind: PodMonitor' <<<"$out" || { echo "PodMonitor rendered without metrics.enabled" >&2; exit 1; }
! grep -q 'kind: NetworkPolicy' <<<"$out" || { echo "NetworkPolicy rendered without networkPolicy.enabled" >&2; exit 1; }

# 2. Enabled: the flag, the named container port and the Service agree.
out=$(render --set metrics.enabled=true)
grep -q -- '"--metrics-bind-address=0.0.0.0:9090"' <<<"$out" || { echo "--metrics-bind-address not rendered from metrics.port" >&2; exit 1; }
port_name=$(render --set metrics.enabled=true --show-only templates/deployment.yaml \
  | yq -r '.spec.template.spec.containers[0].ports[] | select(.name != null) | .name')
[ "$port_name" = "metrics" ] || { echo "named container port = '$port_name', expected metrics" >&2; exit 1; }
container_port=$(render --set metrics.enabled=true --show-only templates/deployment.yaml \
  | yq -r '.spec.template.spec.containers[0].ports[] | select(.name == "metrics") | .containerPort')
svc=$(render --set metrics.enabled=true --show-only templates/service-metrics.yaml)
[ "$(yq -r '.kind' <<<"$svc")" = "Service" ] || { echo "service-metrics.yaml did not render a Service" >&2; exit 1; }
[ "$(yq -r '.spec.type' <<<"$svc")" = "ClusterIP" ] || { echo "metrics Service must be ClusterIP" >&2; exit 1; }
[ "$(yq -r '.spec.ports[0].name' <<<"$svc")" = "metrics" ] || { echo "metrics Service port is not named metrics" >&2; exit 1; }
[ "$(yq -r '.spec.ports[0].port' <<<"$svc")" = "$container_port" ] || { echo "Service port and container port differ" >&2; exit 1; }
# The port is computed once by the metricsPort helper and included as a string;
# a stray newline in that define would render a null or a non-integer scalar
# here, which `yq` reports as a type rather than a value mismatch.
[ "$(yq -r '.spec.ports[0].port | type' <<<"$svc")" = "!!int" ] || { echo "Service port is not an integer scalar" >&2; exit 1; }
[ "$(yq -r '.spec.ports[0].targetPort' <<<"$svc")" = "metrics" ] || { echo "Service targetPort must reference the named port" >&2; exit 1; }
[ "$(yq -r '.metadata.labels["app.kubernetes.io/component"]' <<<"$svc")" = "metrics" ] || { echo "metrics Service lacks the component label" >&2; exit 1; }
! grep -q 'name: metrics' <<<"$(render --set metrics.enabled=true --show-only templates/service.yaml)" || { echo "metrics port leaked onto the main Service" >&2; exit 1; }

# 3. An explicit bind address wins over the derived one.
render --set metrics.enabled=true --set metrics.bindAddress=127.0.0.1:9090 | grep -q -- '"--metrics-bind-address=127.0.0.1:9090"' \
  || { echo "metrics.bindAddress not honoured" >&2; exit 1; }

# 4. Reserved keys refuse to render anything but their default.
! render --set metrics.enabled=true --set metrics.tls.enabled=true >/dev/null 2>&1 || { echo "metrics.tls.enabled=true must fail: not implemented" >&2; exit 1; }
! render --set metrics.enabled=true --set metrics.authentication.mode=delegated >/dev/null 2>&1 || { echo "metrics.authentication.mode=delegated must fail: not implemented" >&2; exit 1; }

# 4b. An upgrade with --reuse-values from a release that predates the metrics
#     and networkPolicy keys renders with those keys absent (nil). Every
#     template must survive that, as _helpers.tpl requires.
render --set metrics=null --set networkPolicy=null >/dev/null || { echo "render fails when metrics/networkPolicy keys are absent (--reuse-values shape)" >&2; exit 1; }

# 4c. A port collision with the proxy or readiness port, an out-of-range port,
#     a bind address that disables the listener or targets another port, and
#     an invalid port name all fail at render time rather than after install.
! render --set metrics.enabled=true --set metrics.port=8080 >/dev/null 2>&1 || { echo "metrics.port=8080 must fail to render" >&2; exit 1; }
! render --set metrics.enabled=true --set metrics.port=8443 >/dev/null 2>&1 || { echo "metrics.port=8443 must fail to render" >&2; exit 1; }
! render --set metrics.enabled=true --set metrics.port=70000 >/dev/null 2>&1 || { echo "metrics.port=70000 must fail to render" >&2; exit 1; }
! render --set metrics.enabled=true --set metrics.bindAddress=0 >/dev/null 2>&1 || { echo "metrics.bindAddress=0 must fail to render" >&2; exit 1; }
! render --set metrics.enabled=true --set metrics.bindAddress=0.0.0.0:9091 >/dev/null 2>&1 || { echo "bindAddress on another port must fail to render" >&2; exit 1; }
! render --set metrics.enabled=true --set metrics.portName=Metrics_Port >/dev/null 2>&1 || { echo "invalid metrics.portName must fail to render" >&2; exit 1; }
# A fractional port passes `int` in the Deployment but reaches the Service as
# 9090.5; a non-numeric one casts to 0. Both must be refused as non-integers,
# with that message rather than the range message.
# `render` fails here, so its output is captured before grepping: piping it
# straight into grep would trip `set -o pipefail` on helm's own exit code.
err=$(render --set metrics.enabled=true --set-json 'metrics.port=9090.5' 2>&1 || true)
grep -q 'metrics.port must be an integer' <<<"$err" || { echo "fractional metrics.port must fail as a non-integer" >&2; exit 1; }
err=$(render --set metrics.enabled=true --set-string metrics.port=abc 2>&1 || true)
grep -q 'metrics.port must be an integer' <<<"$err" || { echo "non-numeric metrics.port must fail as a non-integer" >&2; exit 1; }
# Kubernetes IsValidPortName rejects consecutive dashes and names over 15
# characters; the chart must refuse both at render time.
! render --set metrics.enabled=true --set metrics.portName=a--b >/dev/null 2>&1 || { echo "metrics.portName=a--b must fail to render" >&2; exit 1; }
! render --set metrics.enabled=true --set metrics.portName=abcdefghijklmnop >/dev/null 2>&1 || { echo "a 16-character metrics.portName must fail to render" >&2; exit 1; }

# 4d. A non-default port and name agree everywhere.
out=$(render --set metrics.enabled=true --set metrics.port=9191 --set metrics.portName=observe)
grep -q -- '"--metrics-bind-address=0.0.0.0:9191"' <<<"$out" || { echo "non-default port not in the flag" >&2; exit 1; }
[ "$(render --set metrics.enabled=true --set metrics.port=9191 --set metrics.portName=observe --show-only templates/deployment.yaml | yq -r '.spec.template.spec.containers[0].ports[] | select(.name == "observe") | .containerPort')" = "9191" ] \
  || { echo "non-default named container port missing" >&2; exit 1; }
[ "$(render --set metrics.enabled=true --set metrics.port=9191 --set metrics.portName=observe --show-only templates/service-metrics.yaml | yq -r '.spec.ports[0].targetPort')" = "observe" ] \
  || { echo "non-default Service targetPort missing" >&2; exit 1; }
[ "$(render --set metrics.enabled=true --set metrics.port=9191 --set metrics.portName=observe --show-only templates/service-metrics.yaml | yq -r '.spec.ports[0].port')" = "9191" ] \
  || { echo "non-default Service port missing" >&2; exit 1; }
[ "$(render --set metrics.enabled=true --set metrics.port=9191 --set metrics.portName=observe --set metrics.serviceMonitor.enabled=true --show-only templates/servicemonitor.yaml | yq -r '.spec.endpoints[0].port')" = "observe" ] \
  || { echo "non-default ServiceMonitor endpoint port missing" >&2; exit 1; }


# 4e. Operator labels on the metrics Service cannot override the selector labels.
svc_labels=$(render --set metrics.enabled=true --set 'metrics.service.labels.app\.kubernetes\.io/component=other' --set 'metrics.service.labels.team=platform' --show-only templates/service-metrics.yaml)
[ "$(yq -r '.metadata.labels["app.kubernetes.io/component"]' <<<"$svc_labels")" = "metrics" ] || { echo "operator label overrode the component label" >&2; exit 1; }
[ "$(yq -r '.metadata.labels.team' <<<"$svc_labels")" = "platform" ] || { echo "harmless operator label dropped" >&2; exit 1; }

# 5. extraArgs still renders on top of the metrics block.
render --set metrics.enabled=true --set extraArgs.v=5 --show-only templates/deployment.yaml | grep -q -- '"--v=5"' \
  || { echo "extraArgs did not render after the metrics block" >&2; exit 1; }

# 6. ServiceMonitor references the Service port by name; durations are quoted.
sm=$(render --set metrics.enabled=true --set metrics.serviceMonitor.enabled=true \
  --set metrics.serviceMonitor.interval=30s --set metrics.serviceMonitor.sampleLimit=5000 \
  --show-only templates/servicemonitor.yaml)
[ "$(yq -r '.kind' <<<"$sm")" = "ServiceMonitor" ] || { echo "ServiceMonitor did not render" >&2; exit 1; }
[ "$(yq -r '.spec.endpoints[0].port' <<<"$sm")" = "$port_name" ] || { echo "ServiceMonitor endpoint port != Service port name" >&2; exit 1; }
[ "$(yq -r '.spec.endpoints[0].interval' <<<"$sm")" = "30s" ] || { echo "interval not rendered" >&2; exit 1; }
[ "$(yq -r '.spec.endpoints[0].interval | type' <<<"$sm")" = "!!str" ] || { echo "interval must be a string" >&2; exit 1; }
[ "$(yq -r '.spec.sampleLimit' <<<"$sm")" = "5000" ] || { echo "sampleLimit not rendered" >&2; exit 1; }
[ "$(yq -r '.spec.selector.matchLabels["app.kubernetes.io/component"]' <<<"$sm")" = "metrics" ] || { echo "ServiceMonitor must select the metrics Service by component" >&2; exit 1; }
for limit in sampleLimit targetLimit labelLimit; do
  ! grep -q "$limit" <<<"$(render --set metrics.enabled=true --set metrics.serviceMonitor.enabled=true --show-only templates/servicemonitor.yaml)" \
    || { echo "$limit rendered at 0" >&2; exit 1; }
  [ "$(render --set metrics.enabled=true --set metrics.serviceMonitor.enabled=true --set "metrics.serviceMonitor.$limit=100" --show-only templates/servicemonitor.yaml | yq -r ".spec.$limit")" = "100" ] \
    || { echo "$limit not rendered at 100" >&2; exit 1; }
  # Prometheus rejects a negative limit; `with` used to pass it straight through.
  ! render --set metrics.enabled=true --set metrics.serviceMonitor.enabled=true --set "metrics.serviceMonitor.$limit=-1" >/dev/null 2>&1 \
    || { echo "negative $limit must fail to render" >&2; exit 1; }
  err=$(render --set metrics.enabled=true --set metrics.serviceMonitor.enabled=true --set "metrics.serviceMonitor.$limit=-1" 2>&1 || true)
  grep -q "metrics.serviceMonitor.$limit must be >= 0" <<<"$err" || { echo "negative $limit must fail to render with its own message" >&2; exit 1; }
done

# 7. Exclusions and prerequisites fail loudly.
! render --set metrics.serviceMonitor.enabled=true >/dev/null 2>&1 || { echo "serviceMonitor without metrics.enabled must fail" >&2; exit 1; }
! render --set metrics.enabled=true --set metrics.serviceMonitor.enabled=true --set metrics.podMonitor.enabled=true >/dev/null 2>&1 \
  || { echo "both monitors enabled must fail" >&2; exit 1; }

# 8. PodMonitor targets the named pod port.
pm=$(render --set metrics.enabled=true --set metrics.podMonitor.enabled=true --show-only templates/podmonitor.yaml)
[ "$(yq -r '.spec.podMetricsEndpoints[0].port' <<<"$pm")" = "$port_name" ] || { echo "PodMonitor port != container port name" >&2; exit 1; }

# 9. PrometheusRule renders the groups verbatim and nothing by default.
pr=$(render --set metrics.enabled=true --set metrics.prometheusRule.enabled=true --show-only templates/prometheusrule.yaml)
[ "$(yq -r '.kind' <<<"$pr")" = "PrometheusRule" ] || { echo "PrometheusRule did not render" >&2; exit 1; }
[ "$(yq -r '.spec.groups | length' <<<"$pr")" = "0" ] || { echo "PrometheusRule shipped default groups" >&2; exit 1; }

# 10. NetworkPolicy requires peers, admits them to the metrics port only, and
#     keeps the proxy and readiness ports open.
! render --set metrics.enabled=true --set networkPolicy.enabled=true >/dev/null 2>&1 || { echo "networkPolicy without from must fail" >&2; exit 1; }
np=$(render --set metrics.enabled=true --set networkPolicy.enabled=true \
  --set 'networkPolicy.metrics.from[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=monitoring' \
  --show-only templates/networkpolicy.yaml)
[ "$(yq -r '.spec.ingress[0].ports[0].port' <<<"$np")" = "$port_name" ] || { echo "NetworkPolicy first rule must cover the metrics port" >&2; exit 1; }
[ "$(yq -r '.spec.ingress[0].from | length' <<<"$np")" = "1" ] || { echo "NetworkPolicy peers not rendered" >&2; exit 1; }
[ "$(yq -r '[.spec.ingress[1].ports[].port | tostring] | sort | join(",")' <<<"$np")" = "8080,8443" ] || { echo "NetworkPolicy must keep 8443 and 8080 open to every peer" >&2; exit 1; }
[ "$(yq -r '.spec.ingress[1] | has("from")' <<<"$np")" = "false" ] || { echo "proxy/readiness rule must have no from restriction" >&2; exit 1; }
np_narrow=$(render --set metrics.enabled=true --set networkPolicy.enabled=true --set networkPolicy.additionalIngress=null \
  --set 'networkPolicy.metrics.from[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=monitoring' \
  --show-only templates/networkpolicy.yaml)
[ "$(yq -r '.spec.ingress | length' <<<"$np_narrow")" = "1" ] || { echo "additionalIngress=[] must render only the metrics rule" >&2; exit 1; }

# 11. The ServiceMonitor selector matches the metrics Service labels exactly.
svc_json=$(render --set metrics.enabled=true --show-only templates/service-metrics.yaml | yq -o=json '.metadata.labels')
sm_json=$(render --set metrics.enabled=true --set metrics.serviceMonitor.enabled=true --show-only templates/servicemonitor.yaml | yq -o=json '.spec.selector.matchLabels')
for key in $(yq -r 'keys[]' <<<"$sm_json"); do
  [ "$(yq -r ".[\"$key\"]" <<<"$sm_json")" = "$(yq -r ".[\"$key\"]" <<<"$svc_json")" ] \
    || { echo "ServiceMonitor selector $key does not match the metrics Service label" >&2; exit 1; }
done

echo "chart metrics values: ok"
