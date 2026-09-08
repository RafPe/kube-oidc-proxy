#!/usr/bin/env bash
# Copyright Jetstack Ltd. See LICENSE for details.
set -euo pipefail
# Drive traffic through the demo proxy. --once runs each kind of traffic
# exactly once and exits non-zero if any call did not produce its expected
# status; --duration 10m keeps rotating through them. Everything it needs is
# in hack/metrics-demo/.state, so run up.sh first.
exec go run ./hack/metrics-demo/load --state hack/metrics-demo/.state "$@"
