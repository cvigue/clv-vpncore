#!/bin/bash
# ctest_it6.sh — CTest wrapper for IT6: Masquerade / transit forwarding
#
# Called by CTest via: ctest -L integration
# Escalates to root via sudo if needed.

set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

NUM_CLIENTS=1
RC=0

teardown() {
    "${SCRIPT_DIR}/netns/teardown_vpn.sh" "${NUM_CLIENTS}" 2>/dev/null || true
    # Also tear down the LAN host namespace added by IT6
    ip netns del ns-lan-host 2>/dev/null || true
}
trap teardown EXIT

"${SCRIPT_DIR}/netns/setup_vpn.sh" "${NUM_CLIENTS}"

bash "${SCRIPT_DIR}/test_it6_masquerade.sh" "${PROJECT_ROOT}" || RC=$?

exit "${RC}"
