#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
# shellcheck shell=bash
# Port-forward helper shared by check.sh and verify.sh.
#
# A fixed local port is a correctness bug, not a style one: if a forward left
# behind by an earlier run - or by a different cluster entirely - already holds
# 127.0.0.1:19090, kubectl fails to bind but the curl that follows still gets
# an answer, from someone else's Prometheus. Asking kubectl for port 0 makes it
# pick a free one and announce it, so the announcement is both the port to use
# and the signal that the listener is bound. Each forward is killed on exit and
# checked for liveness before the results that depend on it are trusted.
#
# The port comes back through a caller-named variable rather than on stdout,
# because the bookkeeping below only means anything in the caller's own shell:
# `PROM=$(pf_start ...)` would append the pid and the log to arrays inside a
# command-substitution subshell that exits at once, leaving the EXIT trap with
# nothing to kill and pf_check with nothing to inspect.

PF_PIDS=()
PF_LOGS=()
PF_NAMES=()

# pf_cleanup kills every forward this script started. Call it from a trap.
pf_cleanup() {
  local i
  for i in "${!PF_PIDS[@]}"; do
    kill "${PF_PIDS[$i]}" 2>/dev/null || true
    rm -f "${PF_LOGS[$i]}"
  done
}

# pf_start <outvar> <namespace> <target> <remote-port>; assigns the local port
# it bound to <outvar> in the caller's shell. Every internal carries a pf_
# prefix so that an output variable named after one of them - check.sh asks for
# `port` - is not shadowed by a local and silently discarded.
pf_start() {
  local pf_out=$1 pf_ns=$2 pf_target=$3 pf_remote=$4
  local pf_log pf_port pf_pid
  pf_log=$(mktemp)
  kubectl -n "$pf_ns" port-forward "$pf_target" ":$pf_remote" >"$pf_log" 2>&1 &
  pf_pid=$!
  PF_PIDS+=("$pf_pid")
  PF_LOGS+=("$pf_log")
  PF_NAMES+=("$pf_ns/$pf_target:$pf_remote")

  pf_port=""
  for _ in $(seq 1 150); do
    pf_port=$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]\{1,\}\) ->.*/\1/p' "$pf_log" | head -1)
    [ -n "$pf_port" ] && break
    kill -0 "$pf_pid" 2>/dev/null || break
    sleep 0.2
  done
  if [ -z "$pf_port" ]; then
    echo "port-forward to $pf_ns/$pf_target:$pf_remote never announced a local port:" >&2
    cat "$pf_log" >&2
    return 1
  fi

  printf -v "$pf_out" '%s' "$pf_port"
}

# pf_check fails if any forward has exited, so a query that returns nothing is
# never mistaken for a query that returned nothing interesting.
pf_check() {
  local i
  for i in "${!PF_PIDS[@]}"; do
    if ! kill -0 "${PF_PIDS[$i]}" 2>/dev/null; then
      echo "the port-forward to ${PF_NAMES[$i]} died; its results cannot be trusted:" >&2
      cat "${PF_LOGS[$i]}" >&2
      return 1
    fi
  done
}
