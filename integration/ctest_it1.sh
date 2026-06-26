#!/bin/bash
# ctest_it1.sh — CTest wrapper for IT1: setup → test → teardown
#
# Called by CTest via: ctest -L integration
# Escalates to root via sudo if needed.

set -euo pipefail

# Re-exec under sudo if not already root
if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

NUM_CLIENTS=1
RC=0

# Always teardown, even on failure
teardown() {
    "${SCRIPT_DIR}/netns/teardown_vpn.sh" "${NUM_CLIENTS}" 2>/dev/null || true
}
trap teardown EXIT

# Setup namespaces
"${SCRIPT_DIR}/netns/setup_vpn.sh" "${NUM_CLIENTS}"

# Run the test
"${SCRIPT_DIR}/test_it1_handshake.sh" "${PROJECT_ROOT}" || RC=$?

exit "${RC}"
