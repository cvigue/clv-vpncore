#!/bin/bash
# ctest_it16.sh — CTest wrapper for IT16: openvpn server + simple_vpn client
#
# Called directly or via: sudo integration/ctest_it16.sh
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

bash "${SCRIPT_DIR}/test_it16_ovpn_server_handshake.sh" "${PROJECT_ROOT}" || RC=$?

exit "${RC}"
