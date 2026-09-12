#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
CHART=chart/kube-oidc-proxy
render() { helm template kop "$CHART" --namespace auth --set tls.secretName=serving-tls "$@"; }
check() { yq -e "$1" >/dev/null <<<"$out" || { echo "$2" >&2; exit 1; }; }
deploy='select(.kind == "Deployment") | .spec.template.spec'
container="$deploy.containers[0]"

# Existing single-issuer clients retain flags, Secret references and CA mounts.
out=$(render -f "$CHART/ci/single-issuer-values.yaml" --set oidc.caPEM=test-ca \
  --set oidc.usernamePrefix=user: --set oidc.groupsPrefix=group:)
check "$container.args | contains([\"--oidc-client-id=\$(OIDC_CLIENT_ID)\", \"--oidc-issuer-url=\$(OIDC_ISSUER_URL)\", \"--oidc-username-claim=\$(OIDC_USERNAME_CLAIM)\", \"--oidc-ca-file=/etc/oidc/oidc-ca.pem\", \"--oidc-required-claim=hd=example.com\", \"--oidc-username-prefix=\$(OIDC_USERNAME_PREFIX)\", \"--oidc-groups-prefix=\$(OIDC_GROUPS_PREFIX)\", \"--oidc-groups-claim=\$(OIDC_GROUPS_CLAIM)\", \"--oidc-signing-algs=\$(OIDC_SIGNING_ALGS)\"] )" 'single-issuer flags changed'
check "$container.env[] | select(.name == \"OIDC_CLIENT_ID\") | .valueFrom.secretKeyRef.name == \"kop-kube-oidc-proxy-config\"" 'single-issuer Secret changed'

# Inline configuration still uses the generated Secret, including on old values.
for old_values in false true; do
  opts=(--set authenticationConfig.existingSecret= --set authenticationConfig.key=)
  if [ "$old_values" = true ]; then
    opts=(--set authenticationConfig.existingSecret=null --set authenticationConfig.key=null)
  fi
  out=$(render -f "$CHART/ci/multi-issuer-values.yaml" "${opts[@]}")
  check "$container.args | contains([\"--authentication-config=/etc/oidc/authentication-config.yaml\"])" 'inline config flag missing'
  check 'select(.kind == "Secret" and .metadata.name == "kop-kube-oidc-proxy-config") | .data."authentication-config.yaml" | @base64d | contains("jwt:")' 'inline config missing'
  check "$deploy.volumes[] | select(.name == \"kube-oidc-proxy-config\") | .secret.secretName == \"kop-kube-oidc-proxy-config\"" 'inline Secret changed'
done

# Upgrades with old stored values render exactly as fresh default values.
for fixture in single-issuer multi-issuer; do
  current=$(render -f "$CHART/ci/$fixture-values.yaml")
  old=$(render -f "$CHART/ci/$fixture-values.yaml" \
    --set authenticationConfig.existingSecret=null --set authenticationConfig.key=null)
  [ "$current" = "$old" ] || { echo "$fixture: old values changed the render" >&2; exit 1; }
done
# The external key setting must not alter inline configuration or its checksum.
current=$(render -f "$CHART/ci/multi-issuer-values.yaml")
custom=$(render -f "$CHART/ci/multi-issuer-values.yaml" --set authenticationConfig.key=ignored.yaml)
[ "$current" = "$custom" ] || { echo 'external key changed inline config' >&2; exit 1; }

# External config suppresses every legacy issuer flag/env, even with old values.
for key in authentication-config.yaml custom.yaml; do
  out=$(render -f "$CHART/ci/single-issuer-values.yaml" \
    --set authenticationConfig.existingSecret=external-auth --set "authenticationConfig.key=$key" \
    --set oidc.caPEM=unused --set oidc.usernamePrefix=unused --set oidc.groupsPrefix=unused \
    --set oidc.tlsClient.existingSecret=issuer-mtls --set readinessRequireAllIssuers=true \
    --set 'rbac.userExtras={example.com/team}')
  check "$container.args | contains([\"--authentication-config=/etc/oidc/authentication-config.yaml\", \"--readiness-require-all-issuers\", \"--oidc-tls-client-cert-file=/etc/oidc/client-tls/tls.crt\", \"--oidc-tls-client-key-file=/etc/oidc/client-tls/tls.key\"])" 'external config or shared mTLS flags missing'
  check "$container.args | map(select(test(\"^--oidc-\") and (test(\"^--oidc-tls-client-\") | not))) | length == 0" 'legacy flags in external mode'
  check "$container.env | length == 0" 'legacy env in external mode'
  check "$container.volumeMounts[] | select(.name == \"kube-oidc-proxy-config\") | (.mountPath == \"/etc/oidc\" and .readOnly == true)" 'config mount missing or writable'
  check "$deploy.volumes[] | select(.name == \"kube-oidc-proxy-config\") | (.secret.secretName == \"external-auth\" and (.secret.items | length) == 1 and .secret.items[0].key == \"$key\" and .secret.items[0].path == \"authentication-config.yaml\")" 'external Secret projection incorrect'
  check 'select(.kind == "ClusterRole") | .rules[].resources | select(contains(["userextras/example.com/team"])) | length == 1' 'explicit extra grant missing'
  if yq -e 'select(.kind == "Secret" and (.metadata.name == "external-auth" or .metadata.name == "kop-kube-oidc-proxy-config"))' >/dev/null 2>&1 <<<"$out"; then
    echo 'external mode must not create a configuration Secret' >&2; exit 1
  fi
done

# Missing/empty new keys use the default projection key.
for key in null ''; do
  out=$(render --set authenticationConfig.existingSecret=external-auth --set "authenticationConfig.key=$key")
  check "$deploy.volumes[] | select(.name == \"kube-oidc-proxy-config\") | .secret.items[0].key == \"authentication-config.yaml\"" 'default key missing'
done

# A configuration source conflict must fail clearly.
if out=$(render -f "$CHART/ci/multi-issuer-values.yaml" --set authenticationConfig.existingSecret=external-auth 2>&1); then
  echo 'conflicting configuration sources accepted' >&2; exit 1
fi
[[ "$out" == *'authenticationConfig.content and authenticationConfig.existingSecret are mutually exclusive'* ]] \
  || { echo 'missing source conflict error' >&2; exit 1; }
echo 'chart authentication: ok'
