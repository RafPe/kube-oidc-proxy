#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# The dashboards are documentation for operators: each must be valid Grafana
# JSON with a fixed uid, the shared template variables, a description on every
# panel, a datasource variable on every query, and pass the Grafana dashboard
# linter. The chart must render them only when asked, byte-for-byte.
CHART=chart/kube-oidc-proxy
LINTER_VERSION="0.3.0"
BASE=(--set oidc.issuerUrl=https://x --set oidc.clientId=y)
render() { helm template kop "$CHART" "${BASE[@]}" "$@"; }

# Every published dashboard-linter tag carries a `replace` directive in its
# go.mod, so `go run github.com/grafana/dashboard-linter@vX` refuses to build
# it ("must not contain directives that would cause it to be interpreted
# differently than if it were the main module") and no release binaries are
# published. Build the pinned tag once from a shallow clone, where its own
# go.mod IS the main module, and reuse the binary. Needs git and network.
linter() {
  local bin="bin/dashboard-linter-${LINTER_VERSION}"
  if [ ! -x "$bin" ]; then
    local tmp
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN
    git -c advice.detachedHead=false clone --quiet --depth 1 --branch "v${LINTER_VERSION}" \
      https://github.com/grafana/dashboard-linter "$tmp" 2>/dev/null \
      || { echo "failed to clone dashboard-linter v${LINTER_VERSION}; git and network are required" >&2; return 1; }
    mkdir -p bin
    ( cd "$tmp" && go build -o "$OLDPWD/$bin" . ) \
      || { echo "failed to build dashboard-linter v${LINTER_VERSION}" >&2; return 1; }
  fi
  "$bin" "$@"
}

for f in "$CHART"/dashboards/*.json; do
  name=$(basename "$f" .json)
  jq -e '.uid == "kube-oidc-proxy-'"$name"'"' "$f" >/dev/null || { echo "$f: uid must be kube-oidc-proxy-$name" >&2; exit 1; }
  jq -e '.schemaVersion >= 39 and .editable == false and (.tags | index("kube-oidc-proxy") != null)' "$f" >/dev/null || { echo "$f: schemaVersion/editable/tags" >&2; exit 1; }
  for v in datasource namespace pod; do
    jq -e --arg v "$v" '.templating.list[] | select(.name == $v)' "$f" >/dev/null || { echo "$f: missing template variable $v" >&2; exit 1; }
  done
  jq -e '[.. | objects | select(has("type") and .type != "row" and has("targets")) | select((.description // "") == "")] | length == 0' "$f" >/dev/null \
    || { echo "$f: a panel lacks a description" >&2; exit 1; }
  jq -e '[.. | objects | select(has("expr")) | select(.expr | test("\\$__rate_interval|\\$namespace|kube_oidc_proxy_|go_|process_") | not)] | length == 0' "$f" >/dev/null \
    || { echo "$f: a query does not target this proxy's families" >&2; exit 1; }
  jq -e '[.. | objects | select(has("datasource")) | select(.datasource.uid? != "${datasource}")] | length == 0' "$f" >/dev/null \
    || { echo "$f: a panel or query does not use the datasource variable" >&2; exit 1; }
  # Go's regexp expands "$1xx" as the group NAMED "1xx", which does not exist,
  # so the replacement is empty and every code class collapses into one series.
  # Only "${1}xx" names group 1. Inside a label_replace the template variables
  # are $namespace, $pod and $__rate_interval, none of which start with a
  # digit, so a "$" followed by a digit is always an unbraced group reference.
  jq -e '[.. | objects | select(has("expr")) | select(.expr | test("label_replace\\(")) | select(.expr | test("\\$[0-9]"))] | length == 0' "$f" >/dev/null \
    || { echo "$f: a label_replace replacement uses an unbraced \$<digit>; write \${1} so Go expands the capture group" >&2; exit 1; }
  # A panel that must read zero rather than "No data" ends its query with a
  # `vector(0)` fallback. `vector(0)` carries no labels, so a legendFormat that
  # only interpolates labels renders as a blank row (Grafana shows "Value" when
  # the format is empty). Either the legend is a literal name, or the zero
  # branch is wrapped in a label_replace that gives it every label the legend
  # interpolates.
  jq -e '[.. | objects | select(has("expr")) | select(.expr | test("vector\\(0\\)")) | . as $t | (($t.legendFormat // "")) as $lf | select(($lf | length) == 0 or ([$lf | scan("\\{\\{ *([A-Za-z_][A-Za-z0-9_]*) *\\}\\}")] | flatten | map(. as $n | select($t.expr | test("label_replace\\(.*\"" + $n + "\"") | not)) | length > 0))] | length == 0' "$f" >/dev/null \
    || { echo "$f: a vector(0) fallback has no legendFormat, or one naming labels the zero branch does not carry; use a literal legend or wrap vector(0) in label_replace" >&2; exit 1; }
  # A ratio whose denominator is an ungrouped sum(rate(...)) must give its
  # numerator an `or vector(0)` fallback. Counter children are created the
  # first time an outcome occurs, so on a healthy deployment the deny/reject
  # numerator has no series at all while the denominator has plenty: the
  # division matches nothing and the panel reads "No data" where the honest
  # answer is 0. `vector(0)` has an empty label set and so does an ungrouped
  # `sum`, so the fallback divides cleanly - and when the denominator is
  # itself absent the panel still reads "No data", which is right, because
  # then there is no traffic to take a share of. Ratios that aggregate `by`
  # a label are excluded: an unlabelled zero would draw as an extra series
  # beside the real ones instead of filling a gap.
  jq -e '[.. | objects | select(has("expr"))
          | select(.expr | test("/ sum\\(rate\\("))
          | select(.expr | test("\\(sum\\(rate\\(.*\\) or vector\\(0\\)\\) / sum\\(rate\\(") | not)] | length == 0' "$f" >/dev/null \
    || { echo "$f: a ratio over an ungrouped sum(rate(...)) denominator does not wrap its numerator as (sum(rate(...)) or vector(0)); it reads No data instead of 0 while nothing is denied" >&2; exit 1; }
  # A stat that answers "what is the state now" must query instantly. A range
  # query makes Grafana's stat reduce every series that had a sample anywhere
  # in the window, so after a rollout the build identity of the pods that are
  # gone is listed beside the one that is running for the whole window. Every
  # query over kube_oidc_proxy_build_info reports identity, never a rate, so
  # every one of them is instant.
  jq -e '[.. | objects | select(has("expr")) | select(.expr | test("kube_oidc_proxy_build_info")) | select(.instant != true)] | length == 0' "$f" >/dev/null \
    || { echo "$f: a query over kube_oidc_proxy_build_info is not instant; set \"instant\": true and \"range\": false so a rolled-out pod's identity does not linger for the whole window" >&2; exit 1; }
done

# `lint` takes one dashboard per invocation, so run it per file.
for f in "$CHART"/dashboards/*.json; do
  linter lint --strict "$f"
done

# Off by default; on, one ConfigMap with one key per file, contents identical.
# The render is captured before it is searched: under `set -o pipefail` a
# `! render | grep -q ...` succeeds when *render* fails, so a chart that could
# not be templated at all used to satisfy the "renders nothing" assertion.
default_render=$(render) || { echo "the default render failed" >&2; exit 1; }
! grep -q 'grafana_dashboard' <<<"$default_render" || { echo "dashboards rendered without metrics.dashboards.enabled" >&2; exit 1; }
cm=$(render --set metrics.enabled=true --set metrics.dashboards.enabled=true --show-only templates/dashboards-configmap.yaml)
[ "$(yq -r '.metadata.labels.grafana_dashboard' <<<"$cm")" = "1" ] || { echo "sidecar label missing" >&2; exit 1; }
# No folder and no extra annotations means no annotations block. Helm renders
# a bare `annotations:` key as the value null, and `metadata.annotations: null`
# is a field an apply-time schema check is entitled to reject.
[ "$(yq -r '.metadata | has("annotations")' <<<"$cm")" = "false" ] \
  || { echo "the default dashboards ConfigMap renders a null annotations block" >&2; exit 1; }
[ "$(render --set metrics.enabled=true --set metrics.dashboards.enabled=true --set metrics.dashboards.folder=Platform --show-only templates/dashboards-configmap.yaml | yq -r '.metadata.annotations.grafana_folder')" = "Platform" ] \
  || { echo "metrics.dashboards.folder does not render the grafana_folder annotation" >&2; exit 1; }
# The linter's rule exclusions are a development file, not chart content.
pkg=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$pkg'" EXIT
helm package "$CHART" --destination "$pkg" >/dev/null || { echo "helm package failed" >&2; exit 1; }
! tar -tzf "$pkg"/*.tgz | grep -q 'dashboards/\.lint$' \
  || { echo "the packaged chart carries dashboards/.lint; add it to $CHART/.helmignore" >&2; exit 1; }
for f in "$CHART"/dashboards/*.json; do
  key=$(basename "$f")
  # mikefarah yq (the one this repo's other guards use) has no --arg; strenv
  # passes the key without splicing it into the expression.
  diff <(key="$key" yq -r '.data[strenv(key)]' <<<"$cm" | jq -S .) <(jq -S . "$f") >/dev/null || { echo "ConfigMap key $key differs from the file" >&2; exit 1; }
done
! render --set metrics.dashboards.enabled=true >/dev/null 2>&1 || { echo "dashboards without metrics.enabled must fail" >&2; exit 1; }
echo "chart dashboards: ok"
