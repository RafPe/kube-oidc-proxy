#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# hack/metrics-demo/portforward.sh keeps its bookkeeping - the pids to kill and
# the logs to read and remove - in shell arrays, so it only works when pf_start
# runs in the caller's own shell. Called as `PROM=$(pf_start ...)` the appends
# land in a command-substitution subshell that exits immediately: the caller's
# EXIT trap then kills nothing, every forward outlives the script, and pf_check
# loops over an empty array and passes vacuously, so a dead forward is never
# noticed. Two guards: no caller may invoke pf_start in a subshell, and the
# helper must hand its port back through a named output variable - including
# one named `port`, which check.sh uses and which a `local port` would silently
# shadow.
rc=0

# Guard 1: the call sites. A subshell is where the bookkeeping goes to die.
# shellcheck disable=SC2016  # the literal `$(pf_start` is the thing being sought.
hits=$(grep -n '\$(pf_start\|`pf_start' hack/metrics-demo/*.sh \
  | grep -v '^[^:]*:[0-9]*:[[:space:]]*#' || true)
if [ -n "$hits" ]; then
  echo "pf_start is invoked in a command substitution, so its appends to PF_PIDS/PF_LOGS happen in a subshell and are lost:" >&2
  printf '%s\n' "$hits" | sed 's/^/  /' >&2
  rc=1
fi

# Guard 2: the contract, exercised against a kubectl stub. Three forwards, one
# of them into a variable named `port`; then cleanup must kill every stub and
# remove every log.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/kubectl" <<'STUB'
#!/usr/bin/env bash
# Stand-in for `kubectl port-forward`: announce a distinct local port the way
# kubectl does, then stay alive until killed. Bounded so a guard that fails to
# kill it cannot leave it behind for long.
n=$(cat "$PF_STUB_DIR/n" 2>/dev/null || echo 0)
n=$((n + 1))
printf '%s' "$n" >"$PF_STUB_DIR/n"
echo "Forwarding from 127.0.0.1:$((40000 + n)) -> 9090"
echo "Forwarding from [::1]:$((40000 + n)) -> 9090"
exec sleep 20
STUB
chmod +x "$tmp/kubectl"
export PF_STUB_DIR="$tmp"
PATH="$tmp:$PATH"

fail() { echo "$*" >&2; rc=1; }

# shellcheck source=hack/metrics-demo/portforward.sh
. hack/metrics-demo/portforward.sh

pf_start PROM monitoring svc/prometheus 9090
pf_start GRAFANA monitoring svc/grafana 80
pf_start port proxy pod/kop-0 9090 </dev/null

[ -n "${PROM:-}" ] || fail "pf_start did not assign its output variable PROM"
[ -n "${GRAFANA:-}" ] || fail "pf_start did not assign its output variable GRAFANA"
[ -n "${port:-}" ] || fail "pf_start did not assign the output variable named 'port'; an internal local of that name shadows the caller's"
[ "${PROM:-a}" != "${GRAFANA:-b}" ] || fail "two forwards reported the same local port ${PROM:-}"
[ "${#PF_PIDS[@]}" -eq 3 ] || fail "PF_PIDS holds ${#PF_PIDS[@]} entries in the caller's shell, want 3"
[ "${#PF_LOGS[@]}" -eq 3 ] || fail "PF_LOGS holds ${#PF_LOGS[@]} entries in the caller's shell, want 3"

pids=("${PF_PIDS[@]}")
logs=("${PF_LOGS[@]}")
for l in "${logs[@]}"; do
  [ -f "$l" ] || fail "port-forward log $l is missing before cleanup"
done
pf_check || fail "pf_check reports a dead forward while all three stubs are running"

pf_cleanup

for p in "${pids[@]}"; do
  wait "$p" 2>/dev/null || true
  ! kill -0 "$p" 2>/dev/null || fail "pf_cleanup left the port-forward with pid $p running"
done
for l in "${logs[@]}"; do
  [ ! -e "$l" ] || fail "pf_cleanup left the port-forward log $l behind"
done

[ $rc -eq 0 ] && echo "metrics-demo port-forwards: ok"
exit $rc
