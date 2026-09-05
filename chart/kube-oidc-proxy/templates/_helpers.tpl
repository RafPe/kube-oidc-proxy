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
ClusterRole has to name every key the proxy can emit. Two sources feed it:

  1. `claimMappings.extra[].key` of every issuer in authenticationConfig.content,
     read straight from that YAML so the grant cannot drift from the mapping;
  2. `rbac.userExtras`, for keys that reach the proxy some other way.

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
{{- with .Values.rbac -}}
{{- range (default (list) .userExtras) -}}
{{- $keys = append $keys (toString .) -}}
{{- end -}}
{{- end -}}
{{- $keys | uniq | sortAlpha | toJson -}}
{{- end -}}
