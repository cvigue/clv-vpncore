#!/bin/bash
# ctest_it5.sh — CTest wrapper for IT5: Multi-client DCO
#
# Called by CTest via: ctest -L integration
# Escalates to root via sudo if needed.
# Returns exit code 77 (SKIP) if ovpn-dco module is unavailable.

set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

NUM_CLIENTS=3
RC=0

teardown() {
    "${SCRIPT_DIR}/netns/teardown_vpn.sh" "${NUM_CLIENTS}" 2>/dev/null || true
}
trap teardown EXIT

"${SCRIPT_DIR}/netns/setup_vpn.sh" "${NUM_CLIENTS}"

bash "${SCRIPT_DIR}/test_it5_multi_client_dco.sh" "${PROJECT_ROOT}" || RC=$?

exit "${RC}"
