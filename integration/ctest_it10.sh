#!/bin/bash
# ctest_it10.sh — CTest wrapper for IT10: setup → test → teardown
#
# Called by CTest via: ctest -L integration
# Escalates to root via sudo if needed.

set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

NUM_CLIENTS=2
RC=0

teardown() {
    "${SCRIPT_DIR}/netns/teardown_vpn.sh" "${NUM_CLIENTS}" 2>/dev/null || true
}
trap teardown EXIT

"${SCRIPT_DIR}/netns/setup_vpn.sh" "${NUM_CLIENTS}"

"${SCRIPT_DIR}/test_it10_c2c_route_bypass.sh" "${PROJECT_ROOT}" || RC=$?

exit "${RC}"
