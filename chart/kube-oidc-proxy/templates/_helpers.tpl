{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "kube-oidc-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kube-oidc-proxy.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kube-oidc-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "kube-oidc-proxy.labels" -}}
app.kubernetes.io/name: {{ include "kube-oidc-proxy.name" . }}
helm.sh/chart: {{ include "kube-oidc-proxy.chart" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Extra user-info keys the proxy must be allowed to impersonate.

The API server authorizes every Impersonate-Extra-<key> header separately, as
`impersonate` on `userextras/<key>` in authentication.k8s.io. A key the
ServiceAccount is not granted fails the whole request with 403, so the
ClusterRole has to name every key the proxy can emit. Three sources feed it:

  1. `claimMappings.extra[].key` of every issuer in authenticationConfig.content,
     read straight from that YAML so the grant cannot drift from the mapping;
  2. the keys of `extraImpersonationHeaders.headers` (`k1=v1,k2=v2`), which the
     proxy adds to every impersonated request;
  3. `rbac.userExtras`, for keys that reach the proxy some other way, such as
     Impersonate-Extra-* headers clients send themselves.

Keys are lowercased: the API server lowercases extra keys taken from headers
before authorizing them, and Kubernetes already rejects non-lowercase keys in
claimMappings.extra, so a mixed-case grant would never match a request.

Returns a sorted, de-duplicated JSON array (helpers can only return strings).
*/}}
{{- define "kube-oidc-proxy.userExtraKeys" -}}
{{- $keys := list -}}
{{/*
Every lookup is wrapped in `with`: `helm upgrade --reuse-values` renders with
the values stored by the previous release and does not merge this chart's
defaults, so a key introduced after that release (rbac, and any future one)
is nil rather than its default.
*/}}
{{- with .Values.authenticationConfig -}}
{{- with .content -}}
{{- $cfg := fromYaml . -}}
{{- if hasKey $cfg "Error" -}}
{{- fail (printf "authenticationConfig.content is not valid YAML: %s" (index $cfg "Error")) -}}
{{- end -}}
{{- range $issuer := (default (list) $cfg.jwt) -}}
{{- range $extra := (default (list) (dig "claimMappings" "extra" (list) $issuer)) -}}
{{- with $extra.key -}}{{- $keys = append $keys . -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- with .Values.extraImpersonationHeaders -}}
{{- with .headers -}}
{{- range (splitList "," (toString .)) -}}
{{- with (trim (first (splitList "=" .))) -}}{{- $keys = append $keys . -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- with .Values.rbac -}}
{{- range (default (list) .userExtras) -}}
{{- $keys = append $keys (toString .) -}}
{{- end -}}
{{- end -}}
{{- $lowered := list -}}
{{- range $keys -}}{{- $lowered = append $lowered (lower .) -}}{{- end -}}
{{- $lowered | uniq | sortAlpha | toJson -}}
{{- end -}}

{{/*
Name of the dedicated metrics Service: the full name, shortened so that the
"-metrics" suffix keeps the result within the 63-character Service name limit.
*/}}
{{- define "kube-oidc-proxy.metricsServiceName" -}}
{{- printf "%s-metrics" (include "kube-oidc-proxy.fullname" . | trunc 55 | trimSuffix "-") -}}
{{- end -}}

{{/*
The metrics container and Service port, validated once and returned as an
integer.

Every template that needs the port includes this rather than reading
`metrics.port` itself: the Deployment used to cast with `int` while the
Service and the NOTES emitted the raw value, so `--set-json
'metrics.port=9090.5'` rendered containerPort 9090 next to Service port
9090.5. Casting is not enough on its own — `int` swallows the error and
yields 0 for a non-numeric value — so the raw value is compared with its own
cast before the range checks run, and a non-integer is named as such instead
of being reported as out of range.

Callers pass the root context ($), because the value lookup is absolute.
*/}}
{{- define "kube-oidc-proxy.metricsPort" -}}
{{- $metrics := .Values.metrics | default dict -}}
{{- $raw := dig "port" 9090 $metrics -}}
{{- $port := int $raw -}}
{{- /* The guards fire only for a listener the chart renders; a disabled
     block's values are never read, so they are not validated. */ -}}
{{- $on := dig "enabled" false $metrics -}}
{{- if and $on (ne (toString $port) (toString $raw)) -}}
{{- fail (printf "metrics.port must be an integer, got %v" $raw) -}}
{{- end -}}
{{- if and $on (or (lt $port 1) (gt $port 65535)) -}}
{{- fail "metrics.port must be between 1 and 65535" -}}
{{- end -}}
{{- if and $on (or (eq $port 8443) (eq $port 8080)) -}}
{{- fail "metrics.port must differ from 8443 (the secure port) and 8080 (the readiness port)" -}}
{{- end -}}
{{- $port -}}
{{- end -}}

{{/*
The name of the metrics container and Service port, validated once.

Kubernetes' IsValidPortName is the contract: at most 15 characters, only
lowercase alphanumerics and dashes, at least one letter, no leading or
trailing dash and no consecutive dashes. A single anchored regex cannot
express "no --" without becoming unreadable, so the charset, the letter and
the dash pair are three separate checks.
*/}}
{{- define "kube-oidc-proxy.metricsPortName" -}}
{{- $name := toString (dig "portName" "metrics" (.Values.metrics | default dict)) -}}
{{- $on := dig "enabled" false (.Values.metrics | default dict) -}}
{{- if and $on (not (regexMatch "^[a-z0-9]([-a-z0-9]{0,13}[a-z0-9])?$" $name)) -}}
{{- fail "metrics.portName must be a valid IANA_SVC_NAME: 1-15 lowercase alphanumerics or dashes, not starting or ending with a dash" -}}
{{- end -}}
{{- if and $on (not (regexMatch "[a-z]" $name)) -}}
{{- fail "metrics.portName must contain at least one letter" -}}
{{- end -}}
{{- if and $on (contains "--" $name) -}}
{{- fail "metrics.portName must not contain consecutive dashes" -}}
{{- end -}}
{{- $name -}}
{{- end -}}

{{/* Validate explicit external OIDC sources without reading Secret contents. */}}
{{- define "kube-oidc-proxy.validateOIDCSecret" -}}
{{- $oidc := .Values.oidc -}}
{{- $keys := $oidc.secretKeys | default dict -}}
{{- $auth := .Values.authenticationConfig | default dict -}}
{{- if not (kindIs "map" $keys) -}}
{{- fail "oidc.secretKeys must be a map" -}}
{{- end -}}
{{- if and $keys (not $oidc.existingSecret) -}}
{{- fail "oidc.secretKeys requires oidc.existingSecret" -}}
{{- end -}}
{{- if $oidc.existingSecret -}}
{{- if or $auth.content $auth.existingSecret -}}
{{- fail "oidc.existingSecret and authenticationConfig are mutually exclusive" -}}
{{- end -}}
{{- if eq $oidc.existingSecret (printf "%s-config" (include "kube-oidc-proxy.fullname" .)) -}}
{{- fail "oidc.existingSecret must not name the chart-managed configuration Secret" -}}
{{- end -}}
{{- range $field := list "clientId" "issuerUrl" "usernameClaim" -}}
{{- if index $oidc $field -}}
{{- fail (printf "oidc.%s must be empty when oidc.existingSecret is set" $field) -}}
{{- end -}}
{{- end -}}
{{- range $field, $key := $keys -}}
{{- if not (has $field (list "clientId" "issuerUrl" "usernameClaim" "usernamePrefix" "groupsClaim" "groupsPrefix" "signingAlgs")) -}}
{{- fail (printf "oidc.secretKeys contains unsupported field %s" $field) -}}
{{- end -}}
{{- if $key -}}
{{- if not (kindIs "string" $key) -}}
{{- fail (printf "oidc.secretKeys.%s must be a string" $field) -}}
{{- end -}}
{{- if or (gt (len $key) 253) (not (regexMatch "^[A-Za-z0-9._-]+$" $key)) -}}
{{- fail (printf "oidc.secretKeys.%s must be a valid Secret key" $field) -}}
{{- end -}}
{{- if index $oidc $field -}}
{{- fail (printf "oidc.%s and oidc.secretKeys.%s are mutually exclusive; clear the inline value to use the Secret key" $field $field) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Select the source of an OIDC environment variable. Required fields always
come from the external Secret; optional fields do so only when mapped. */}}
{{- define "kube-oidc-proxy.oidcSecretRef" -}}
{{- $root := .root -}}
{{- $keys := $root.Values.oidc.secretKeys | default dict -}}
{{- $key := index $keys .field -}}
{{- if and $root.Values.oidc.existingSecret (or .required $key) -}}
name: {{ $root.Values.oidc.existingSecret | quote }}
key: {{ $key | default .key | quote }}
{{- else -}}
name: {{ include "kube-oidc-proxy.fullname" $root }}-config
key: {{ .key }}
{{- end -}}
{{- end -}}
