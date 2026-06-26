#!/bin/bash
# ctest_it18.sh — CTest wrapper for IT18: openvpn server (tls-crypt-v2) + simple_vpn client
#
# Called directly or via: sudo integration/ctest_it18.sh
# Returns exit code 77 (SKIP) if openvpn is not installed.

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
}
trap teardown EXIT

"${SCRIPT_DIR}/netns/setup_vpn.sh" "${NUM_CLIENTS}"

bash "${SCRIPT_DIR}/test_it18_ovpn_server_v2.sh" "${PROJECT_ROOT}" || RC=$?

exit "${RC}"
