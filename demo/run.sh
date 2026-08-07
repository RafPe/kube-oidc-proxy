#!/usr/bin/env bash
#
# One-command, self-contained, multi-issuer demo for kube-oidc-proxy.
#
# It stands up a local kind cluster, two Dex OIDC issuers (dex-a, dex-b), and
# kube-oidc-proxy configured with a single AuthenticationConfiguration that
# trusts BOTH issuers. It then mints an ID token from each Dex (via the
# password grant, no browser) and proves that both tokens authenticate through
# the one proxy as distinct impersonated users.
#
# On success the cluster is left running so you can poke it. Run ./cleanup.sh
# to tear it down.
set -euo pipefail

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
CLUSTER="kube-oidc-proxy-demo"
CTX="kind-${CLUSTER}"
DEX_IMAGE="ghcr.io/dexidp/dex:v2.44.0"
PROXY_IMAGE="kube-oidc-proxy:demo"
PROXY_NS="kube-oidc-proxy"
PROXY_RELEASE="kube-oidc-proxy"
CLIENT_SECRET="demo-client-secret"
PASSWORD="password"
# bcrypt hash of PASSWORD ("password"), used by both Dex static users.
BCRYPT_HASH='$2a$10$Z5ozIZvkgAWpm1LX.c0V1.BRXkYYS4vNDcZSJQm5mcDdS8IRXJ0x2'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFESTS="${SCRIPT_DIR}/manifests"
GEN="${SCRIPT_DIR}/.generated"
CERTS="${GEN}/certs"
CA_CRT="${CERTS}/ca.crt"

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
BLUE=$'\033[1;34m'; GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; NC=$'\033[0m'
log()  { echo "${BLUE}==>${NC} $*"; }
ok()   { echo "${GREEN}  ok:${NC} $*"; }
fail() { echo "${RED}ERROR:${NC} $*" >&2; exit 1; }

PF_PIDS=()
cleanup_pf() {
  for pid in "${PF_PIDS[@]:-}"; do
    [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
  done
  PF_PIDS=()
}
# Kill any port-forwards on exit; leave the cluster up on success.
trap cleanup_pf EXIT

require_tool() { command -v "$1" >/dev/null 2>&1 || fail "required tool not found: $1"; }

# Start a background port-forward and wait until the local port answers.
port_forward() { # <local_port> <remote_port> <-n ns> <svc/name>
  local lport="$1" rport="$2"; shift 2
  kubectl --context "${CTX}" port-forward "$@" "${lport}:${rport}" >/dev/null 2>&1 &
  local pid=$!
  PF_PIDS+=("${pid}")
  local i
  for i in $(seq 1 30); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${lport}") 2>/dev/null; then
      exec 3>&- 3<&- || true
      return 0
    fi
    sleep 1
  done
  fail "port-forward to local port ${lport} did not become ready"
}

# Mint an ID token from a Dex issuer via the password grant.
mint_token() { # <dex_name> <username>
  local name="$1" user="$2" host="$1.dex.svc.cluster.local" token
  port_forward 5556 5556 -n dex "svc/${name}"
  token="$(curl -s \
    --resolve "${host}:5556:127.0.0.1" \
    --cacert "${CA_CRT}" \
    "https://${host}:5556/dex/token" \
    -d grant_type=password \
    -d scope="openid email groups" \
    -d client_id=demo \
    -d client_secret="${CLIENT_SECRET}" \
    -d username="${user}" \
    -d password="${PASSWORD}" | jq -r '.id_token // empty')"
  cleanup_pf
  [ -n "${token}" ] || fail "failed to mint token for ${user} from ${name}"
  printf '%s' "${token}"
}

write_kubeconfig() { # <token> <outfile>
  cat >"$2" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: proxy
    cluster:
      server: https://127.0.0.1:8443
      insecure-skip-tls-verify: true
contexts:
  - name: proxy
    context:
      cluster: proxy
      user: oidc
current-context: proxy
users:
  - name: oidc
    user:
      token: $1
EOF
}

# --------------------------------------------------------------------------
# 0. Preflight
# --------------------------------------------------------------------------
log "Checking prerequisites"
for t in kind docker kubectl helm openssl jq curl go; do require_tool "$t"; done
docker info >/dev/null 2>&1 || fail "docker daemon is not running"
ok "all tools present, docker daemon up"

rm -rf "${GEN}"
mkdir -p "${CERTS}"

# --------------------------------------------------------------------------
# 1. Build the proxy image (the chart's pinned image is not published)
# --------------------------------------------------------------------------
log "Building kube-oidc-proxy binary (linux amd64 + arm64)"
( cd "${REPO_ROOT}" \
  && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-w' -o ./bin/amd64/kube-oidc-proxy ./cmd/. \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '-w' -o ./bin/arm64/kube-oidc-proxy ./cmd/. )
ok "binaries built"

log "Building docker image ${PROXY_IMAGE}"
docker build -q -t "${PROXY_IMAGE}" "${REPO_ROOT}" >/dev/null
ok "image built"

# --------------------------------------------------------------------------
# 2. Create the kind cluster
# --------------------------------------------------------------------------
if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
  log "Deleting pre-existing kind cluster ${CLUSTER}"
  kind delete cluster --name "${CLUSTER}" >/dev/null
fi
log "Creating kind cluster ${CLUSTER}"
kind create cluster --name "${CLUSTER}" >/dev/null
ok "cluster ready"

log "Loading images into the cluster"
kind load docker-image "${PROXY_IMAGE}" --name "${CLUSTER}" >/dev/null
# Pull Dex locally then side-load it so pod startup needs no registry pull.
docker pull -q "${DEX_IMAGE}" >/dev/null
kind load docker-image "${DEX_IMAGE}" --name "${CLUSTER}" >/dev/null
ok "images loaded"

# --------------------------------------------------------------------------
# 3. Generate a CA and a serving certificate per Dex (SAN = svc DNS)
# --------------------------------------------------------------------------
log "Generating TLS certificates"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
  -keyout "${CERTS}/ca.key" -out "${CA_CRT}" \
  -subj "/CN=kube-oidc-proxy-demo-ca" \
  -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1

gen_cert() { # <name>
  local name="$1"
  openssl req -newkey rsa:2048 -nodes -sha256 \
    -keyout "${CERTS}/${name}.key" -out "${CERTS}/${name}.csr" \
    -subj "/CN=${name}.dex.svc.cluster.local" >/dev/null 2>&1
  openssl x509 -req -in "${CERTS}/${name}.csr" \
    -CA "${CA_CRT}" -CAkey "${CERTS}/ca.key" -CAcreateserial \
    -out "${CERTS}/${name}.crt" -days 3650 -sha256 \
    -extfile <(printf 'subjectAltName=DNS:%s.dex.svc.cluster.local,DNS:%s.dex,DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "${name}" "${name}" "${name}") \
    >/dev/null 2>&1
}
gen_cert dex-a
gen_cert dex-b
ok "CA + dex-a/dex-b serving certs generated"

# --------------------------------------------------------------------------
# 4. Deploy the two Dex issuers
# --------------------------------------------------------------------------
log "Deploying Dex issuers (dex-a: alice, dex-b: bob)"
kubectl --context "${CTX}" create namespace dex >/dev/null

render_dex() { # <name> <email> <username> <userid>
  sed \
    -e "s|__NAME__|$1|g" \
    -e "s|__ISSUER__|https://$1.dex.svc.cluster.local:5556/dex|g" \
    -e "s|__CLIENT_SECRET__|${CLIENT_SECRET}|g" \
    -e "s|__USER_EMAIL__|$2|g" \
    -e "s|__USER_NAME__|$3|g" \
    -e "s|__USER_ID__|$4|g" \
    -e "s|__HASH__|${BCRYPT_HASH}|g" \
    -e "s|__IMAGE__|${DEX_IMAGE}|g" \
    "${MANIFESTS}/dex.yaml.tpl"
}

for pair in "dex-a alice@example.com alice alice-id" "dex-b bob@example.com bob bob-id"; do
  set -- ${pair}
  kubectl --context "${CTX}" create secret tls "$1-tls" -n dex \
    --cert "${CERTS}/$1.crt" --key "${CERTS}/$1.key" >/dev/null
  render_dex "$1" "$2" "$3" "$4" | kubectl --context "${CTX}" apply -f - >/dev/null
done

kubectl --context "${CTX}" -n dex rollout status deploy/dex-a --timeout=120s
kubectl --context "${CTX}" -n dex rollout status deploy/dex-b --timeout=120s
ok "both Dex issuers are ready"

# --------------------------------------------------------------------------
# 5. Render the AuthenticationConfiguration (inline CA) and install the proxy
# --------------------------------------------------------------------------
log "Rendering multi-issuer AuthenticationConfiguration"
CA_INDENTED="$(sed 's/^/        /' "${CA_CRT}")"
# Replace each __CA_x__ marker line with the indented CA PEM. Done in pure bash
# so it does not depend on awk's handling of multi-line variables (BSD awk on
# macOS rejects embedded newlines in -v values).
: >"${GEN}/authentication-config.yaml"
while IFS= read -r line || [ -n "${line}" ]; do
  case "${line}" in
    __CA_A__|__CA_B__) printf '%s\n' "${CA_INDENTED}" ;;
    *)                 printf '%s\n' "${line}" ;;
  esac
done <"${MANIFESTS}/authentication-config.yaml.tpl" >>"${GEN}/authentication-config.yaml"
ok "authentication-config.yaml written"

log "Installing kube-oidc-proxy via Helm (multi-issuer mode)"
helm --kube-context "${CTX}" install "${PROXY_RELEASE}" \
  "${REPO_ROOT}/chart/kube-oidc-proxy" \
  --namespace "${PROXY_NS}" --create-namespace \
  -f "${MANIFESTS}/proxy-values.yaml" \
  --set-file authenticationConfig.content="${GEN}/authentication-config.yaml" \
  --wait --timeout 180s >/dev/null
ok "proxy pod is Ready (both issuers initialized)"

log "Applying demo RBAC (view for both OIDC identities)"
kubectl --context "${CTX}" apply -f "${MANIFESTS}/rbac.yaml" >/dev/null
ok "RBAC applied"

# --------------------------------------------------------------------------
# 6. Mint a token from each issuer
# --------------------------------------------------------------------------
log "Minting ID tokens (password grant, no browser)"
TOKEN_A="$(mint_token dex-a alice@example.com)"
ok "minted dex-a token for alice@example.com"
TOKEN_B="$(mint_token dex-b bob@example.com)"
ok "minted dex-b token for bob@example.com"

# --------------------------------------------------------------------------
# 7. Authenticate through the single proxy with BOTH tokens
# --------------------------------------------------------------------------
log "Port-forwarding the proxy and testing both identities"
port_forward 8443 443 -n "${PROXY_NS}" "svc/${PROXY_RELEASE}"

write_kubeconfig "${TOKEN_A}" "${GEN}/kubeconfig-a.yaml"
write_kubeconfig "${TOKEN_B}" "${GEN}/kubeconfig-b.yaml"

check_identity() { # <kubeconfig> <expected_user> <label>
  local kcfg="$1" expected="$2" label="$3" out
  echo
  echo "${BLUE}--- ${label}: expecting user \"${expected}\" ---${NC}"

  echo "\$ kubectl get pods -A   (allowed by the 'view' ClusterRoleBinding)"
  out="$(kubectl --kubeconfig "${kcfg}" get pods -A 2>&1)" \
    || fail "${label}: 'get pods' failed:\n${out}"
  echo "${out}" | head -n 6
  echo "  ... ($(echo "${out}" | grep -c . ) lines total)"

  # 'view' does not grant secrets; the API server echoes the impersonated
  # username in the forbidden error -> unambiguous identity proof.
  echo "\$ kubectl get secrets -A   (denied; error names the impersonated user)"
  out="$(kubectl --kubeconfig "${kcfg}" get secrets -A 2>&1 || true)"
  echo "${out}" | head -n 2
  echo "${out}" | grep -q "\"${expected}\"" \
    || fail "${label}: forbidden error did not name expected user ${expected}:\n${out}"
  ok "authenticated through the proxy as ${expected}"
}

check_identity "${GEN}/kubeconfig-a.yaml" "oidc-a:alice@example.com" "Issuer A (dex-a)"
check_identity "${GEN}/kubeconfig-b.yaml" "oidc-b:bob@example.com"   "Issuer B (dex-b)"

cleanup_pf

echo
echo "${GREEN}SUCCESS:${NC} both issuers authenticate through the single proxy."
echo "The cluster '${CLUSTER}' is left running. Tear it down with: ./cleanup.sh"
