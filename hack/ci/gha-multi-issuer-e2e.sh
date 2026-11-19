#!/usr/bin/env bash
#
# Multi-issuer e2e against the REAL GitHub Actions OIDC issuer.
#
# Stands up a kind cluster and installs kube-oidc-proxy (Helm chart) in
# multi-issuer mode with TWO issuers configured in a single
# AuthenticationConfiguration:
#
#   (a) https://token.actions.githubusercontent.com  -- the genuine external
#       GitHub Actions OIDC IdP (public JWKS, no certificateAuthority). Its
#       `sub` claim is mapped to the impersonated username with a "gha:" prefix.
#   (b) a local Dex issuer (self-signed, in-cluster) -- proves the union
#       authenticator still serves a second, private issuer. Its `email` claim
#       is mapped with an "oidc-local:" prefix.
#
# `readinessRequireAllIssuers: true` makes the proxy report Ready only once it
# has initialised BOTH issuers -- including fetching the real GitHub Actions
# JWKS over the public internet. So a Ready proxy already proves multi-issuer
# initialisation against the real IdP.
#
# Assertions:
#   * Local Dex token authenticates + impersonates "oidc-local:alice@example.com".
#   * (CI only, when a GitHub Actions ID token is provided via GHA_TOKEN_FILE)
#     that token authenticates + impersonates "gha:<sub>" through the SAME proxy.
#
# Identity is proven the same way the demo does it: a request the user is NOT
# allowed to make (get secrets) is denied with a Forbidden error that echoes the
# impersonated username.
#
# GHA_CONFIG_KIND=proxy runs the same flow with the proxy kind
# kube-oidc-proxy.rafpe.github.io/v1alpha1 (ADR-0001). The document has three
# issuers on the GitHub Actions issuer URL, each with its own name and
# audience, and the local Dex issuer:
#
#   gha-internal  audience GHA_AUDIENCE           pins repository_owner_id
#   gha-vendor    audience GHA_AUDIENCE-vendor    pins repository_owner_id
#   gha-foreign   audience GHA_AUDIENCE-foreign   pins repository_owner_id "0"
#
# The GitHub Actions issuers map the username with
# authenticationConfiguration.issuer.name + ":" + claims.sub. Assertions in
# this mode, with real GitHub Actions tokens minted per audience:
#   * The GHA_AUDIENCE token impersonates "gha-internal:<sub>".
#   * The vendor token impersonates "gha-vendor:<sub>".
#   * The foreign token gets 401: the router selects gha-foreign, its claim
#     rule refuses the token, and no other issuer verifies it.
#   * A token with an audience that no issuer has gets 401, and the proxy
#     logs authn.oidc.failed with reason=audience_unrouted.
#   * The access records carry issuer_name gha-internal and gha-vendor.
#   * Each issuer maps a different extra key, so the requests also prove the
#     chart RBAC for the extra keys of issuers[].jwt.
#
# Environment:
#   GHA_CONFIG_KIND upstream (default) or proxy. See above.
#   GHA_TOKEN_FILE  Optional path to a file containing a GitHub Actions OIDC ID
#                   token (minted in-workflow via core.getIDToken). When set, the
#                   GHA-token assertions run; when unset, only issuer (a) config +
#                   the local Dex assertions run (used for local verification).
#   GHA_AUDIENCE    Audience the token was minted with. Default:
#                   kube-oidc-proxy-kind-test. MUST match GHA_TOKEN_FILE's aud.
#   KEEP_CLUSTER    If "true", leave the kind cluster running on exit.
set -euo pipefail

CLUSTER="kube-oidc-proxy-gha-e2e"
CTX="kind-${CLUSTER}"
DEX_IMAGE="ghcr.io/dexidp/dex:v2.44.0"
PROXY_IMAGE="kube-oidc-proxy:gha-e2e"
PROXY_NS="kube-oidc-proxy"
PROXY_RELEASE="kube-oidc-proxy"
DEX_NAME="dex-local"
DEX_USER="alice@example.com"
CLIENT_SECRET="demo-client-secret"
PASSWORD="password"
BCRYPT_HASH='$2a$10$Z5ozIZvkgAWpm1LX.c0V1.BRXkYYS4vNDcZSJQm5mcDdS8IRXJ0x2'
GHA_ISSUER="https://token.actions.githubusercontent.com"
GHA_AUDIENCE="${GHA_AUDIENCE:-kube-oidc-proxy-kind-test}"
GHA_TOKEN_FILE="${GHA_TOKEN_FILE:-}"
GHA_CONFIG_KIND="${GHA_CONFIG_KIND:-upstream}"
case "${GHA_CONFIG_KIND}" in
  upstream|proxy) ;;
  *) echo "GHA_CONFIG_KIND must be upstream or proxy, not ${GHA_CONFIG_KIND}" >&2; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEMO_MANIFESTS="${REPO_ROOT}/demo/manifests"
CHART="${REPO_ROOT}/chart/kube-oidc-proxy"
GEN="$(mktemp -d)"
CERTS="${GEN}/certs"
CA_CRT="${CERTS}/ca.crt"

BLUE=$'\033[1;34m'; GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; NC=$'\033[0m'
log()  { echo "${BLUE}==>${NC} $*"; }
ok()   { echo "${GREEN}  ok:${NC} $*"; }
fail() { echo "${RED}ERROR:${NC} $*" >&2; exit 1; }

PF_PIDS=()
cleanup() {
  for pid in "${PF_PIDS[@]:-}"; do [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true; done
  if [ "${KEEP_CLUSTER:-false}" != "true" ]; then
    kind delete cluster --name "${CLUSTER}" >/dev/null 2>&1 || true
  fi
  rm -rf "${GEN}" 2>/dev/null || true
}
trap cleanup EXIT

require_tool() { command -v "$1" >/dev/null 2>&1 || fail "required tool not found: $1"; }

# base64url-decode a JWT segment (adds padding, maps url alphabet).
b64url_decode() {
  local d="$1"; local pad=$(( (4 - ${#d} % 4) % 4 ))
  local i; for ((i=0;i<pad;i++)); do d="${d}="; done
  echo "${d}" | tr '_-' '/+' | base64 -d 2>/dev/null
}
jwt_claim() { # <token> <claim>
  local payload; payload="$(printf '%s' "$1" | cut -d. -f2)"
  b64url_decode "${payload}" | jq -r ".$2 // empty"
}

port_forward() { # <local_port> <remote_port> <-n ns> <svc/name>
  local lport="$1" rport="$2"; shift 2
  kubectl --context "${CTX}" port-forward "$@" "${lport}:${rport}" >/dev/null 2>&1 &
  PF_PIDS+=("$!")
  local i
  for i in $(seq 1 30); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${lport}") 2>/dev/null; then exec 3>&- 3<&- || true; return 0; fi
    sleep 1
  done
  fail "port-forward to local port ${lport} did not become ready"
}
stop_pf() { for pid in "${PF_PIDS[@]:-}"; do [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true; done; PF_PIDS=(); }

mint_dex_token() {
  local host="${DEX_NAME}.dex.svc.cluster.local" token
  port_forward 5556 5556 -n dex "svc/${DEX_NAME}"
  token="$(curl -s \
    --resolve "${host}:5556:127.0.0.1" --cacert "${CA_CRT}" \
    "https://${host}:5556/dex/token" \
    -d grant_type=password -d scope="openid email groups" \
    -d client_id=demo -d client_secret="${CLIENT_SECRET}" \
    -d username="${DEX_USER}" -d password="${PASSWORD}" | jq -r '.id_token // empty')"
  stop_pf
  [ -n "${token}" ] || fail "failed to mint Dex token for ${DEX_USER}"
  printf '%s' "${token}"
}

write_kubeconfig() { # <token> <outfile>
  cat >"$2" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: proxy
    cluster: { server: https://127.0.0.1:8443, insecure-skip-tls-verify: true }
contexts:
  - name: proxy
    context: { cluster: proxy, user: oidc }
current-context: proxy
users:
  - name: oidc
    user: { token: $1 }
EOF
}

# assert an identity: allowed 'get pods', denied 'get secrets' naming the user.
check_identity() { # <kubeconfig> <expected_user> <label>
  local kcfg="$1" expected="$2" label="$3" out
  echo; echo "${BLUE}--- ${label}: expecting user \"${expected}\" ---${NC}"
  out="$(kubectl --kubeconfig "${kcfg}" get pods -A 2>&1)" \
    || fail "${label}: 'get pods' failed (view should allow it):\n${out}"
  ok "'get pods' allowed via the 'view' binding"
  out="$(kubectl --kubeconfig "${kcfg}" get secrets -A 2>&1 || true)"
  echo "${out}" | grep -q "\"${expected}\"" \
    || fail "${label}: forbidden error did not name expected user ${expected}:\n${out}"
  ok "authenticated + impersonated through the proxy as ${expected}"
}

# assert that the proxy refuses the token with HTTP 401 and that the
# authn.oidc.failed record of that request carries the expected reason. The
# check reads the status code, because the kubectl error text differs between
# versions. The Audit-ID response header is the request_id of the record.
check_unauthorized() { # <token> <reason> <label>
  local token="$1" reason="$2" label="$3" headers code request_id
  echo; echo "${BLUE}--- ${label}: expecting 401 with reason=${reason} ---${NC}"
  [ -n "${token}" ] || fail "${label}: the token is empty"
  headers="$(mktemp)"
  code="$(curl -sk -o /dev/null -D "${headers}" -w '%{http_code}' \
    -H "Authorization: Bearer ${token}" https://127.0.0.1:8443/api/v1/pods)"
  request_id="$(tr -d '\r' < "${headers}" | awk 'tolower($1) == "audit-id:" { print $2 }' | tail -n 1)"
  rm -f "${headers}"
  [ "${code}" = "401" ] || fail "${label}: the proxy answered ${code}, not 401"
  [ -n "${request_id}" ] || fail "${label}: the 401 response has no Audit-ID header"
  ok "the proxy refused the token with 401 (request_id ${request_id})"
  check_log ".event_type == \"authn.oidc.failed\" and .request_id == \"${request_id}\" and .reason == \"${reason}\"" \
    "authn.oidc.failed of request ${request_id} carries reason=${reason}"
}

# mint a GitHub Actions ID token for an audience. The runner OIDC endpoint
# mints any audience. Without it, only GHA_TOKEN_FILE, minted for
# GHA_AUDIENCE, is available.
mint_gha_token() { # <audience>
  local aud="$1" token=""
  if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
    token="$(curl -fsS -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
      "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=$(jq -rn --arg a "${aud}" '$a | @uri')" | jq -r '.value // empty')" || token=""
  fi
  if [ -z "${token}" ] && [ "${aud}" = "${GHA_AUDIENCE}" ]; then
    token="$(cat "${GHA_TOKEN_FILE}")"
  fi
  [ -n "${token}" ] || fail "cannot mint a GitHub Actions token for audience ${aud}"
  printf '%s' "${token}"
}

# assert that the proxy log has a JSON record that matches a jq filter.
check_log() { # <jq filter> <label>
  local filter="$1" label="$2"
  # Read every proxy pod: the port-forward and the log can select other pods.
  kubectl --context "${CTX}" -n "${PROXY_NS}" logs --tail=-1 --prefix=false \
    -l "app.kubernetes.io/instance=${PROXY_RELEASE}" \
    | jq -cR "fromjson? | select(${filter})" | grep -q . \
    || fail "${label}: no proxy log record matches ${filter}"
  ok "${label}"
}

check_impersonation() { # <kubeconfig> <caller> <label>
  local kcfg="$1" caller="$2" label="$3" out
  echo; echo "${BLUE}--- ${label}: kubectl --as through the proxy as \"${caller}\" ---${NC}"
  # Allowed: the caller may impersonate ci-viewer, and ci-viewer may view.
  # This needs the proxy's ServiceAccount to create SubjectAccessReviews; a
  # chart that does not grant that fails here with a 500, not a 403.
  out="$(kubectl --kubeconfig "${kcfg}" --as=ci-viewer get pods -A 2>&1)" \
    || fail "${label}: '--as=ci-viewer get pods' failed (impersonation grant + view should allow it):\n${out}"
  ok "--as=ci-viewer allowed: SubjectAccessReview created and granted"
  # Refused by the proxy itself, before anything is forwarded: the caller has
  # no grant for this target, so the review says no and the proxy answers 403.
  out="$(kubectl --kubeconfig "${kcfg}" --as=nobody get pods -A 2>&1 || true)"
  echo "${out}" | grep -q "is not allowed to impersonate user" \
    || fail "${label}: '--as=nobody' was not refused by the proxy's impersonation check:\n${out}"
  ok "--as=nobody refused by the proxy (403 impersonation_denied, not a 500)"
}

# --------------------------------------------------------------------------
log "Preflight"
for t in kind docker kubectl helm openssl jq curl go; do require_tool "$t"; done
docker info >/dev/null 2>&1 || fail "docker daemon is not running"
if [ -n "${GHA_TOKEN_FILE}" ]; then
  [ -s "${GHA_TOKEN_FILE}" ] || fail "GHA_TOKEN_FILE=${GHA_TOKEN_FILE} is empty/missing"
  ok "GitHub Actions token provided -> GHA-token assertions enabled"
else
  ok "no GitHub Actions token -> configuring GHA issuer, testing local issuer only"
fi

log "Building proxy image ${PROXY_IMAGE}"
( cd "${REPO_ROOT}" \
  && ldflags="-w $(hack/version-ldflags.sh)" \
  && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "${ldflags}" -o ./bin/amd64/kube-oidc-proxy ./cmd/. \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "${ldflags}" -o ./bin/arm64/kube-oidc-proxy ./cmd/. )
docker build -q -t "${PROXY_IMAGE}" "${REPO_ROOT}" >/dev/null
ok "image built"

if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
  kind delete cluster --name "${CLUSTER}" >/dev/null
fi
log "Creating kind cluster ${CLUSTER}"
kind create cluster --name "${CLUSTER}" >/dev/null
kind load docker-image "${PROXY_IMAGE}" --name "${CLUSTER}" >/dev/null
# The node pulls Dex from ghcr itself: on ubuntu-26.04 runners, kind load of the
# pulled multi-platform image fails in ctr images import --all-platforms.
ok "cluster ready, proxy image loaded"

log "Generating TLS for the local Dex issuer"
mkdir -p "${CERTS}"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
  -keyout "${CERTS}/ca.key" -out "${CA_CRT}" \
  -subj "/CN=kube-oidc-proxy-gha-e2e-ca" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -keyout "${CERTS}/${DEX_NAME}.key" -out "${CERTS}/${DEX_NAME}.csr" \
  -subj "/CN=${DEX_NAME}.dex.svc.cluster.local" >/dev/null 2>&1
openssl x509 -req -in "${CERTS}/${DEX_NAME}.csr" \
  -CA "${CA_CRT}" -CAkey "${CERTS}/ca.key" -CAcreateserial \
  -out "${CERTS}/${DEX_NAME}.crt" -days 3650 -sha256 \
  -extfile <(printf 'subjectAltName=DNS:%s.dex.svc.cluster.local,DNS:%s.dex,DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "${DEX_NAME}" "${DEX_NAME}" "${DEX_NAME}") \
  >/dev/null 2>&1
ok "CA + ${DEX_NAME} serving cert generated"

log "Deploying local Dex issuer (user ${DEX_USER})"
kubectl --context "${CTX}" create namespace dex >/dev/null
kubectl --context "${CTX}" create secret tls "${DEX_NAME}-tls" -n dex \
  --cert "${CERTS}/${DEX_NAME}.crt" --key "${CERTS}/${DEX_NAME}.key" >/dev/null
sed \
  -e "s|__NAME__|${DEX_NAME}|g" \
  -e "s|__ISSUER__|https://${DEX_NAME}.dex.svc.cluster.local:5556/dex|g" \
  -e "s|__CLIENT_SECRET__|${CLIENT_SECRET}|g" \
  -e "s|__USER_EMAIL__|${DEX_USER}|g" \
  -e "s|__USER_NAME__|alice|g" \
  -e "s|__USER_ID__|alice-id|g" \
  -e "s|__HASH__|${BCRYPT_HASH}|g" \
  -e "s|__IMAGE__|${DEX_IMAGE}|g" \
  "${DEMO_MANIFESTS}/dex.yaml.tpl" | kubectl --context "${CTX}" apply -f - >/dev/null
kubectl --context "${CTX}" -n dex rollout status "deploy/${DEX_NAME}" --timeout=120s
ok "local Dex is ready"

CA_INDENTED="$(sed 's/^/            /' "${CA_CRT}")"
if [ "${GHA_CONFIG_KIND}" = "proxy" ]; then
log "Rendering the proxy-kind AuthenticationConfiguration (3 x GHA on one URL + local Dex)"
# The owner of the repository that runs the workflow. Without a token, the
# GitHub Actions assertions do not run, and any value loads.
GHA_OWNER_ID=""
if [ -n "${GHA_TOKEN_FILE}" ]; then
  GHA_OWNER_ID="$(jwt_claim "$(cat "${GHA_TOKEN_FILE}")" repository_owner_id)"
fi
GHA_OWNER_ID="${GHA_OWNER_ID:-${GITHUB_REPOSITORY_OWNER_ID:-1}}"
CA_INDENTED_PROXY="$(sed 's/^/              /' "${CA_CRT}")"
gha_issuer() { # <name> <audience> <owner id> <extra key> <extra claim>
  cat <<EOF
  - name: $1
    jwt:
      issuer:
        url: ${GHA_ISSUER}
        audiences:
          - $2
      claimMappings:
        username:
          expression: 'authenticationConfiguration.issuer.name + ":" + claims.sub'
        extra:
          - key: $4
            valueExpression: claims.$5
      claimValidationRules:
        - expression: 'claims.repository_owner_id == "$3"'
          message: only the owner $3
EOF
}
{
  cat <<EOF
apiVersion: kube-oidc-proxy.rafpe.github.io/v1alpha1
kind: AuthenticationConfiguration
issuers:
EOF
  gha_issuer gha-internal "${GHA_AUDIENCE}" "${GHA_OWNER_ID}" github.com/repository repository
  gha_issuer gha-vendor "${GHA_AUDIENCE}-vendor" "${GHA_OWNER_ID}" github.com/ref ref
  gha_issuer gha-foreign "${GHA_AUDIENCE}-foreign" 0 github.com/workflow workflow
  cat <<EOF
  - name: dex-local
    jwt:
      issuer:
        url: https://${DEX_NAME}.dex.svc.cluster.local:5556/dex
        audiences:
          - demo
        certificateAuthority: |
${CA_INDENTED_PROXY}
      claimMappings:
        username:
          claim: email
          prefix: "oidc-local:"
        groups:
          claim: groups
          prefix: "oidc-local:"
        extra:
          - key: example.com/email
            valueExpression: claims.email
EOF
} >"${GEN}/authentication-config.yaml"
ok "authentication-config.yaml rendered (proxy kind, owner ${GHA_OWNER_ID})"
else
log "Rendering multi-issuer AuthenticationConfiguration (GHA + local Dex)"
cat >"${GEN}/authentication-config.yaml" <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: ${GHA_ISSUER}
      audiences:
        - ${GHA_AUDIENCE}
    claimMappings:
      username:
        claim: sub
        prefix: "gha:"
      # An extra mapping makes every request carry Impersonate-Extra-<key>,
      # which the API server authorizes as userextras/<key>. The request only
      # succeeds if the chart's ClusterRole granted the key it read from this
      # very configuration.
      extra:
        - key: github.com/repository
          valueExpression: claims.repository
  - issuer:
      url: https://${DEX_NAME}.dex.svc.cluster.local:5556/dex
      audiences:
        - demo
      certificateAuthority: |
${CA_INDENTED}
    claimMappings:
      username:
        claim: email
        prefix: "oidc-local:"
      groups:
        claim: groups
        prefix: "oidc-local:"
      extra:
        - key: example.com/email
          valueExpression: claims.email
EOF
ok "authentication-config.yaml rendered (GHA issuer has no certificateAuthority; both issuers map an extra)"
fi

log "Installing kube-oidc-proxy via Helm (multi-issuer, readinessRequireAllIssuers)"
# The proxy mode reads the DEBUG record authn.oidc.failed, so it sets --v=1.
HELM_EXTRA=()
if [ "${GHA_CONFIG_KIND}" = "proxy" ]; then
  HELM_EXTRA+=(--set-string logging.verbosity=1)
fi
helm --kube-context "${CTX}" install "${PROXY_RELEASE}" "${CHART}" ${HELM_EXTRA[@]+"${HELM_EXTRA[@]}"} \
  --namespace "${PROXY_NS}" --create-namespace \
  --set image.repository=kube-oidc-proxy \
  --set image.tag=gha-e2e \
  --set image.pullPolicy=Never \
  --set readinessRequireAllIssuers=true \
  --set-file authenticationConfig.content="${GEN}/authentication-config.yaml" \
  --wait --timeout 180s >/dev/null
ok "proxy Ready -> every issuer initialised (real GitHub Actions JWKS fetched)"

log "Applying RBAC (view) for the impersonated identities"
kubectl --context "${CTX}" create clusterrolebinding gha-e2e-local-view \
  --clusterrole=view --user="oidc-local:${DEX_USER}" >/dev/null

# Inbound impersonation (kubectl --as): the proxy authorizes it with a
# SubjectAccessReview it must be allowed to create, then forwards as the
# target. A ClusterRole scoped to one target username, bound to each
# identity under test; the target itself may only view.
kubectl --context "${CTX}" create clusterrole gha-e2e-impersonate-ci-viewer \
  --verb=impersonate --resource=users --resource-name=ci-viewer >/dev/null
kubectl --context "${CTX}" create clusterrolebinding gha-e2e-ci-viewer-view \
  --clusterrole=view --user=ci-viewer >/dev/null
kubectl --context "${CTX}" create clusterrolebinding gha-e2e-local-impersonate \
  --clusterrole=gha-e2e-impersonate-ci-viewer --user="oidc-local:${DEX_USER}" >/dev/null
GHA_SUB=""
if [ -n "${GHA_TOKEN_FILE}" ]; then
  GHA_TOKEN="$(cat "${GHA_TOKEN_FILE}")"
  # GitHub Actions OIDC tokens expire five minutes after minting, and the
  # cluster setup above takes ~4m50s on a stock runner -- with the token
  # minted before this script started, reaching this point unexpired was a
  # race decided by seconds (observed: passes at 4m52s-4m57s, a 401 at
  # 5m02s). When the runner exposes its OIDC endpoint (the job has
  # id-token: write), swap in a token minted NOW so expiry can never win.
  if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
    log "Re-minting the GitHub Actions token at point of use (5-minute expiry vs ~5-minute setup)"
    FRESH_GHA_TOKEN="$(curl -fsS -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
      "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=$(jq -rn --arg a "${GHA_AUDIENCE}" '$a | @uri')" | jq -r '.value // empty')" || FRESH_GHA_TOKEN=""
    if [ -n "${FRESH_GHA_TOKEN}" ]; then
      GHA_TOKEN="${FRESH_GHA_TOKEN}"
    else
      log "WARN: re-mint failed; falling back to the pre-minted token"
    fi
  fi
  GHA_SUB="$(jwt_claim "${GHA_TOKEN}" sub)"
  [ -n "${GHA_SUB}" ] || fail "could not decode 'sub' from the GitHub Actions token"
  log "GitHub Actions token sub=${GHA_SUB}"
  if [ "${GHA_CONFIG_KIND}" = "proxy" ]; then
    GHA_USERS=("gha-internal:${GHA_SUB}" "gha-vendor:${GHA_SUB}")
  else
    GHA_USERS=("gha:${GHA_SUB}")
  fi
  for u in "${GHA_USERS[@]}"; do
    n="$(printf '%s' "${u%%:*}")"
    kubectl --context "${CTX}" create clusterrolebinding "gha-e2e-${n}-view" \
      --clusterrole=view --user="${u}" >/dev/null
    kubectl --context "${CTX}" create clusterrolebinding "gha-e2e-${n}-impersonate" \
      --clusterrole=gha-e2e-impersonate-ci-viewer --user="${u}" >/dev/null
  done
fi
ok "RBAC applied"

# Mint the local Dex token FIRST: mint_dex_token runs its own Dex port-forward
# and tears it down (stop_pf) when done. Doing this before the proxy forward
# exists means stop_pf only kills the Dex forward -- so we never kill and
# re-bind local 8443, which was racy (intermittent "connection refused").
log "Minting a local Dex token"
DEX_TOKEN="$(mint_dex_token)"

# Establish the proxy port-forward ONCE and keep it for every assertion below.
log "Port-forwarding the proxy"
port_forward 8443 443 -n "${PROXY_NS}" "svc/${PROXY_RELEASE}"

# ---- Assertion 1: local Dex issuer works through the multi-issuer proxy.
# Every request carries the mapped extra, so a passing 'get pods' also proves
# the chart granted userextras/example.com/email to the proxy's ServiceAccount.
write_kubeconfig "${DEX_TOKEN}" "${GEN}/kubeconfig-local.yaml"
check_identity "${GEN}/kubeconfig-local.yaml" "oidc-local:${DEX_USER}" "Local Dex issuer"
check_impersonation "${GEN}/kubeconfig-local.yaml" "oidc-local:${DEX_USER}" "Local Dex issuer"

# ---- Assertion 2 (CI only): the real GitHub Actions token authenticates,
# with its own extra (userextras/github.com/repository) and --as.
if [ -n "${GHA_TOKEN_FILE}" ] && [ "${GHA_CONFIG_KIND}" = "upstream" ]; then
  log "Authenticating the real GitHub Actions token through the proxy"
  write_kubeconfig "${GHA_TOKEN}" "${GEN}/kubeconfig-gha.yaml"
  check_identity "${GEN}/kubeconfig-gha.yaml" "gha:${GHA_SUB}" "GitHub Actions issuer"
  check_impersonation "${GEN}/kubeconfig-gha.yaml" "gha:${GHA_SUB}" "GitHub Actions issuer"
fi

# ---- Assertion 3 (CI only, proxy kind): three issuers on one issuer URL.
# Each token is minted at point of use for its own audience. Each token goes
# into a variable first: a failed mint inside a command argument does not stop
# the script under set -e.
if [ -n "${GHA_TOKEN_FILE}" ] && [ "${GHA_CONFIG_KIND}" = "proxy" ]; then
  log "Routing real GitHub Actions tokens between issuers of one issuer URL"
  token="$(mint_gha_token "${GHA_AUDIENCE}")"
  write_kubeconfig "${token}" "${GEN}/kubeconfig-gha-internal.yaml"
  check_identity "${GEN}/kubeconfig-gha-internal.yaml" "gha-internal:${GHA_SUB}" "Issuer gha-internal"
  check_impersonation "${GEN}/kubeconfig-gha-internal.yaml" "gha-internal:${GHA_SUB}" "Issuer gha-internal"

  token="$(mint_gha_token "${GHA_AUDIENCE}-vendor")"
  write_kubeconfig "${token}" "${GEN}/kubeconfig-gha-vendor.yaml"
  check_identity "${GEN}/kubeconfig-gha-vendor.yaml" "gha-vendor:${GHA_SUB}" "Issuer gha-vendor"

  token="$(mint_gha_token "${GHA_AUDIENCE}-foreign")"
  check_unauthorized "${token}" unauthorized "Issuer gha-foreign, which pins another owner"
  token="$(mint_gha_token "${GHA_AUDIENCE}-unrouted")"
  check_unauthorized "${token}" audience_unrouted "An audience that no issuer has"

  echo; echo "${BLUE}--- proxy log records ---${NC}"
  check_log '.event_type == "request.access.decided" and .issuer_name == "gha-internal" and .decision == "allow"' \
    "an access record names issuer gha-internal"
  check_log '.event_type == "request.access.decided" and .issuer_name == "gha-vendor" and .decision == "allow"' \
    "an access record names issuer gha-vendor"
fi

stop_pf
echo
echo "${GREEN}SUCCESS:${NC} multi-issuer proxy verified."
if [ -n "${GHA_TOKEN_FILE}" ] && [ "${GHA_CONFIG_KIND}" = "upstream" ]; then
  echo "  - real GitHub Actions OIDC token impersonated as gha:${GHA_SUB}, with extra github.com/repository"
fi
if [ -n "${GHA_TOKEN_FILE}" ] && [ "${GHA_CONFIG_KIND}" = "proxy" ]; then
  echo "  - one GitHub Actions issuer URL, three issuers: gha-internal:${GHA_SUB} and gha-vendor:${GHA_SUB} accepted,"
  echo "    gha-foreign refused by its claim rule, an unknown audience refused as audience_unrouted"
fi
echo "  - local Dex token impersonated as oidc-local:${DEX_USER}, with extra example.com/email"
echo "  - kubectl --as=ci-viewer allowed for both, --as=nobody refused by the proxy"
