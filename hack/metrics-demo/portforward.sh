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

# pf_start <namespace> <target> <remote-port>; prints the local port it bound.
pf_start() {
  local ns=$1 target=$2 remote=$3
  local log port pid i
  log=$(mktemp)
  kubectl -n "$ns" port-forward "$target" ":$remote" >"$log" 2>&1 &
  pid=$!
  PF_PIDS+=("$pid")
  PF_LOGS+=("$log")
  PF_NAMES+=("$ns/$target:$remote")

  port=""
  for _ in $(seq 1 150); do
    port=$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]\{1,\}\) ->.*/\1/p' "$log" | head -1)
    [ -n "$port" ] && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  if [ -z "$port" ]; then
    echo "port-forward to $ns/$target:$remote never announced a local port:" >&2
    cat "$log" >&2
    return 1
  fi

  printf '%s\n' "$port"
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
