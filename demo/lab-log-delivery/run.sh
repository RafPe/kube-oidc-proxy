#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
#
# Log-delivery lab: run the docs/log-shipping.md recipe against a local AWS
# emulator, on top of the demo cluster that ../run.sh creates.
#
#   proxy stdout (audit events + structured log)
#     -> aws-for-fluent-bit DaemonSet
#     -> two Kinesis streams        (Floci)
#     -> two Firehose delivery streams, Kinesis stream as source
#     -> one S3 bucket              (Floci)
#
# It ends by making one request through the proxy and showing that request's
# audit event and structured log record on the Kinesis streams and inside S3.
# Everything stays in the demo cluster; ./cleanup.sh removes the lab pieces,
# ../cleanup.sh removes the cluster.
set -euo pipefail

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
CLUSTER="kube-oidc-proxy-demo"
CTX="kind-${CLUSTER}"
PROXY_NS="kube-oidc-proxy"
PROXY_RELEASE="kube-oidc-proxy"
FLOCI_NS="floci"
FLB_NS="aws-for-fluent-bit"
FLB_CHART_VERSION="0.2.0"
REGION="eu-west-1"
BUCKET="kube-oidc-proxy-logs"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${DEMO_DIR}/.." && pwd)"
GEN="${SCRIPT_DIR}/.generated"

# The emulator accepts any credentials. The CLI reaches it through a
# port-forward; the agent inside the cluster uses the Service name.
export AWS_ACCESS_KEY_ID=lab AWS_SECRET_ACCESS_KEY=lab AWS_DEFAULT_REGION="${REGION}" AWS_PAGER=""
awsl() { aws --endpoint-url http://127.0.0.1:4566 "$@"; }

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
BLUE=$'\033[1;34m'; GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; NC=$'\033[0m'
log()  { echo "${BLUE}==>${NC} $*"; }
ok()   { echo "${GREEN}  ok:${NC} $*"; }
fail() { echo "${RED}ERROR:${NC} $*" >&2; exit 1; }
k()    { kubectl --context "${CTX}" "$@"; }

PF_PIDS=()
cleanup_pf() { for pid in "${PF_PIDS[@]:-}"; do [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true; done; PF_PIDS=(); }
trap cleanup_pf EXIT

port_forward() { # <local_port> <remote_port> <-n ns> <svc/name>
  local lport="$1" rport="$2"; shift 2
  # A listener that is already there would answer in our place and point the
  # CLI at something else (a stale port-forward, typically). Refuse to guess.
  if (exec 3<>"/dev/tcp/127.0.0.1/${lport}") 2>/dev/null; then
    exec 3>&- 3<&- || true
    fail "local port ${lport} is already in use; stop whatever listens there (lsof -i :${lport}) and re-run"
  fi
  # kubectl directly, not through k(): $! must be kubectl's own PID so the
  # EXIT trap kills the listener rather than a wrapper subshell.
  kubectl --context "${CTX}" port-forward "$@" "${lport}:${rport}" >/dev/null 2>&1 &
  PF_PIDS+=("$!")
  for _ in $(seq 1 30); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${lport}") 2>/dev/null; then exec 3>&- 3<&- || true; return 0; fi
    sleep 1
  done
  fail "port-forward to local port ${lport} did not become ready"
}

# --------------------------------------------------------------------------
# 0. Preflight: tools, the demo cluster and what the demo generated
# --------------------------------------------------------------------------
log "Checking prerequisites"
for t in kind kubectl helm aws jq openssl grep; do
  command -v "$t" >/dev/null 2>&1 || fail "required tool not found: $t"
done
kind get clusters 2>/dev/null | grep -qx "${CLUSTER}" \
  || fail "kind cluster ${CLUSTER} not found; run ../run.sh first"
for f in authentication-config.yaml kubeconfig-a.yaml; do
  [ -f "${DEMO_DIR}/.generated/${f}" ] || fail "missing ${DEMO_DIR}/.generated/${f}; run ../run.sh first"
done
helm repo add eks https://aws.github.io/eks-charts >/dev/null 2>&1 || true
helm repo update eks >/dev/null
mkdir -p "${GEN}"
ok "demo cluster present, tools present"

# --------------------------------------------------------------------------
# 1. Turn on audit logging to stdout (docs/log-shipping.md "What you need")
# --------------------------------------------------------------------------
log "Enabling the proxy's audit log on stdout"
k apply -f "${SCRIPT_DIR}/manifests/audit-policy.yaml" >/dev/null
helm --kube-context "${CTX}" upgrade "${PROXY_RELEASE}" "${REPO_ROOT}/chart/kube-oidc-proxy" \
  --namespace "${PROXY_NS}" \
  -f "${DEMO_DIR}/manifests/proxy-values.yaml" \
  -f "${SCRIPT_DIR}/values/proxy-audit.yaml" \
  --set-file authenticationConfig.content="${DEMO_DIR}/.generated/authentication-config.yaml" \
  --wait --timeout 180s >/dev/null
ok "proxy rolled out with --audit-log-path=-"

# --------------------------------------------------------------------------
# 2. The AWS emulator, behind a TLS front the agent can talk to
# --------------------------------------------------------------------------
SAN="floci.${FLOCI_NS}.svc.cluster.local"
if [ ! -f "${GEN}/ca.crt" ] || [ ! -f "${GEN}/tls.crt" ]; then
  # Kept in .generated across runs: a fresh CA on every run would leave the
  # emulator serving yesterday's certificate and the agent trusting today's CA.
  log "Generating a CA and a serving certificate for the emulator"
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
    -keyout "${GEN}/ca.key" -out "${GEN}/ca.crt" -subj "/CN=lab-log-delivery-ca" \
    -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -sha256 -keyout "${GEN}/tls.key" -out "${GEN}/tls.csr" \
    -subj "/CN=${SAN}" >/dev/null 2>&1
  openssl x509 -req -in "${GEN}/tls.csr" -CA "${GEN}/ca.crt" -CAkey "${GEN}/ca.key" -CAcreateserial \
    -out "${GEN}/tls.crt" -days 365 -sha256 \
    -extfile <(printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "${SAN}") \
    >/dev/null 2>&1
fi

log "Deploying Floci (AWS emulator)"
k create namespace "${FLOCI_NS}" --dry-run=client -o yaml | k apply -f - >/dev/null
SECRET_STATE="$(k -n "${FLOCI_NS}" create secret tls floci-tls --cert "${GEN}/tls.crt" --key "${GEN}/tls.key" \
  --dry-run=client -o yaml | k apply -f -)"
k apply -f "${SCRIPT_DIR}/manifests/floci.yaml" >/dev/null
# nginx reads the certificate once at start: a changed Secret needs a restart.
case "${SECRET_STATE}" in *configured*) k -n "${FLOCI_NS}" rollout restart deploy/floci >/dev/null ;; esac
k create namespace "${FLB_NS}" --dry-run=client -o yaml | k apply -f - >/dev/null
CA_STATE="$(k -n "${FLB_NS}" create configmap floci-ca --from-file=ca.crt="${GEN}/ca.crt" \
  --dry-run=client -o yaml | k apply -f -)"
# Same for the agent, which loads the CA when its TLS context is built.
case "${CA_STATE}" in *configured*)
  k -n "${FLB_NS}" get ds aws-for-fluent-bit >/dev/null 2>&1 && k -n "${FLB_NS}" rollout restart ds/aws-for-fluent-bit >/dev/null ;;
esac
k -n "${FLOCI_NS}" rollout status deploy/floci --timeout=300s >/dev/null
ok "Floci is up at floci.${FLOCI_NS}.svc.cluster.local (4566 plain, 443 TLS)"

# --------------------------------------------------------------------------
# 3. The "AWS side": two streams, one bucket, Firehose from each stream to S3
# --------------------------------------------------------------------------
log "Creating Kinesis streams, the S3 bucket and the Firehose delivery streams"
port_forward 4566 4566 -n "${FLOCI_NS}" svc/floci
# Each create tolerates "already exists" so a re-run picks up where it left off.
for s in kube-oidc-proxy-audit kube-oidc-proxy-logs; do
  awsl kinesis describe-stream-summary --stream-name "$s" >/dev/null 2>&1 \
    || awsl kinesis create-stream --stream-name "$s" --stream-mode-details StreamMode=ON_DEMAND >/dev/null
  awsl kinesis wait stream-exists --stream-name "$s"
done
awsl s3api head-bucket --bucket "${BUCKET}" >/dev/null 2>&1 || awsl s3 mb "s3://${BUCKET}" >/dev/null
ROLE="arn:aws:iam::000000000000:role/lab"   # never evaluated by the emulator
for pair in "kube-oidc-proxy-audit audit/" "kube-oidc-proxy-logs logs/"; do
  set -- ${pair}
  awsl firehose describe-delivery-stream --delivery-stream-name "$1-to-s3" >/dev/null 2>&1 && continue
  awsl firehose create-delivery-stream \
    --delivery-stream-name "$1-to-s3" \
    --delivery-stream-type KinesisStreamAsSource \
    --kinesis-stream-source-configuration "{\"KinesisStreamARN\":\"arn:aws:kinesis:${REGION}:000000000000:stream/$1\",\"RoleARN\":\"${ROLE}\"}" \
    --s3-destination-configuration "{\"RoleARN\":\"${ROLE}\",\"BucketARN\":\"arn:aws:s3:::${BUCKET}\",\"Prefix\":\"$2\",\"BufferingHints\":{\"SizeInMBs\":1,\"IntervalInSeconds\":60},\"CompressionFormat\":\"UNCOMPRESSED\"}" \
    >/dev/null
done
ok "streams kube-oidc-proxy-audit and kube-oidc-proxy-logs; bucket ${BUCKET}; Firehose to audit/ and logs/"

# --------------------------------------------------------------------------
# 4. The agent (docs/log-shipping.md "Agent side")
# --------------------------------------------------------------------------
log "Installing aws-for-fluent-bit ${FLB_CHART_VERSION}"
helm --kube-context "${CTX}" upgrade --install aws-for-fluent-bit eks/aws-for-fluent-bit \
  --namespace "${FLB_NS}" --version "${FLB_CHART_VERSION}" \
  -f "${SCRIPT_DIR}/values/fluent-bit.yaml" --wait --timeout 300s >/dev/null
ok "agent DaemonSet is running"

# --------------------------------------------------------------------------
# 5. One request through the proxy, then follow its ID down the chain
# --------------------------------------------------------------------------
log "Making one request through the proxy as alice (demo token)"
port_forward 8443 443 -n "${PROXY_NS}" "svc/${PROXY_RELEASE}"
kubectl --kubeconfig "${DEMO_DIR}/.generated/kubeconfig-a.yaml" get pods -n kube-system >/dev/null \
  || fail "request through the proxy failed; the demo token may have expired, re-run ../run.sh"
sleep 2
AUDIT_ID="$(k -n "${PROXY_NS}" logs "deploy/${PROXY_RELEASE}" --tail=300 \
  | jq -r 'select(.kind == "Event" and .verb == "list" and .objectRef.namespace == "kube-system") | .auditID' \
  | tail -1)"
[ -n "${AUDIT_ID}" ] || fail "no audit event for the request on the proxy's stdout"
ok "request audited on stdout, auditID ${AUDIT_ID}"

log "Agent output metrics (docs/log-shipping.md Verify, step 1)"
k -n "${FLB_NS}" exec ds/aws-for-fluent-bit -- curl -s localhost:2020/api/v1/metrics \
  | jq -c '.output | to_entries[] | {output: .key, proc_records: .value.proc_records, dropped_records: .value.dropped_records, retries_failed: .value.retries_failed}'

read_stream() { # <stream> -> every record on shard 0, one JSON object per line
  local shard it
  shard="$(awsl kinesis list-shards --stream-name "$1" --query 'Shards[0].ShardId' --output text)"
  it="$(awsl kinesis get-shard-iterator --stream-name "$1" --shard-id "${shard}" \
        --shard-iterator-type TRIM_HORIZON --query ShardIterator --output text)"
  awsl kinesis get-records --shard-iterator "${it}" --limit 1000 --output json \
    | jq -r '.Records[].Data | @base64d'
}

log "Waiting for the request's records on the Kinesis streams (Verify, step 2)"
AUDIT_REC=""; LOG_REC=""
for _ in $(seq 1 18); do
  AUDIT_REC="$(read_stream kube-oidc-proxy-audit | jq -c "select(.data.auditID == \"${AUDIT_ID}\") | {auditID: .data.auditID, stage: .data.stage, verb: .data.verb, user: .data.user.username}" | head -1)"
  LOG_REC="$(read_stream kube-oidc-proxy-logs | jq -c "select(.data.request_id == \"${AUDIT_ID}\" and .data.event_type == \"request.access.decided\") | {event_type: .data.event_type, request_id: .data.request_id, decision: .data.decision, k8s_verb: .data.k8s_verb, k8s_resource: .data.k8s_resource}" | head -1)"
  [ -n "${AUDIT_REC}" ] && [ -n "${LOG_REC}" ] && break
  sleep 5
done
[ -n "${AUDIT_REC}" ] || fail "audit event ${AUDIT_ID} did not reach kube-oidc-proxy-audit within 90s"
[ -n "${LOG_REC}" ]   || fail "log record ${AUDIT_ID} did not reach kube-oidc-proxy-logs within 90s"
echo "  audit stream: ${AUDIT_REC}"
echo "  logs stream:  ${LOG_REC}"
ok "both records are on their streams, joined on request_id == auditID"

log "Waiting for Firehose to deliver them into s3://${BUCKET} (buffering 60s)"
FOUND_A=""; FOUND_L=""
for _ in $(seq 1 15); do
  rm -rf "${GEN}/s3"; mkdir -p "${GEN}/s3"
  awsl s3 sync "s3://${BUCKET}/" "${GEN}/s3/" >/dev/null 2>&1 || true
  FOUND_A="$(grep -rl "${AUDIT_ID}" "${GEN}/s3/audit" 2>/dev/null | head -1 || true)"
  FOUND_L="$(grep -rl "${AUDIT_ID}" "${GEN}/s3/logs"  2>/dev/null | head -1 || true)"
  [ -n "${FOUND_A}" ] && [ -n "${FOUND_L}" ] && break
  sleep 15
done
[ -n "${FOUND_A}" ] || fail "no S3 object under audit/ contains ${AUDIT_ID} after 225s"
[ -n "${FOUND_L}" ] || fail "no S3 object under logs/ contains ${AUDIT_ID} after 225s"
echo "  ${FOUND_A#"${GEN}/s3/"}"
grep "${AUDIT_ID}" "${FOUND_A}" | jq -c '{auditID: .data.auditID, stage: .data.stage, verb: .data.verb, user: .data.user.username, pod: .kubernetes.pod_name}'
echo "  ${FOUND_L#"${GEN}/s3/"}"
grep "${AUDIT_ID}" "${FOUND_L}" | jq -c 'select(.data.event_type == "request.access.decided") | {event_type: .data.event_type, request_id: .data.request_id, decision: .data.decision, pod: .kubernetes.pod_name}'
ok "the same two records are objects in S3"

cleanup_pf
echo
echo "${GREEN}SUCCESS:${NC} audit event and log record for one request reached S3 via Kinesis."
echo "Poke at it:  kubectl --context ${CTX} -n ${FLOCI_NS} port-forward svc/floci 4566:4566 &"
echo "             AWS_ACCESS_KEY_ID=lab AWS_SECRET_ACCESS_KEY=lab aws --endpoint-url http://127.0.0.1:4566 --region ${REGION} s3 ls s3://${BUCKET}/ --recursive"
echo "Tear down:   ./cleanup.sh (lab pieces only) or ../cleanup.sh (the whole cluster)"
