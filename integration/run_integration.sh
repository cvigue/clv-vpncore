#!/bin/bash
# run_integration.sh — Run all VPN integration tests.
#
# Manages the full lifecycle: namespace creation, test execution, teardown.
# Each test scenario is independent; namespaces are rebuilt between tests
# to ensure isolation.
#
# Usage: sudo ./run_integration.sh [PROJECT_ROOT]
#
# Exit code: 0 if all tests pass, 1 otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

PASS=0
FAIL=0
RESULTS=()

# ── Helpers ──────────────────────────────────────────────────────────

run_test() {
    local name="$1"
    local num_clients="$2"
    local script="$3"

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ${name}"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    # Setup
    echo "--- Setup (${num_clients} client(s)) ---"
    "${SCRIPT_DIR}/netns/setup_vpn.sh" "${num_clients}"
    echo ""

    # Run
    local rc=0
    "${script}" "${PROJECT_ROOT}" || rc=$?

    # Teardown
    echo ""
    echo "--- Teardown ---"
    "${SCRIPT_DIR}/netns/teardown_vpn.sh" "${num_clients}"

    if (( rc == 0 )); then
        (( PASS++ )) || true
        RESULTS+=("PASS  ${name}")
    else
        (( FAIL++ )) || true
        RESULTS+=("FAIL  ${name}")
    fi
}

# ── Preconditions ────────────────────────────────────────────────────

if [[ $(id -u) -ne 0 ]]; then
    echo "Error: Integration tests require root."
    exit 1
fi

BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"
if [[ ! -x "${BINARY}" ]]; then
    echo "Error: simple_vpn not found at ${BINARY}"
    echo "       Build with: ninja -C build"
    exit 1
fi

echo "=== VPN Integration Test Suite ==="
echo "    Project root: ${PROJECT_ROOT}"
echo "    Binary:       ${BINARY}"

# ── Test execution ───────────────────────────────────────────────────

run_test "IT1: Single Client Handshake + Ping" 1 \
    "${SCRIPT_DIR}/test_it1_handshake.sh"

run_test "IT2: Multi-Client Concurrent Connect" 3 \
    "${SCRIPT_DIR}/test_it2_multi_client.sh"

# IT4: DCO data path — skip if kernel module unavailable
if modprobe -n ovpn-dco 2>/dev/null || modprobe -n ovpn-dco-v2 2>/dev/null; then
    run_test "IT4: DCO Data Path (Kernel Offload)" 1 \
        "${SCRIPT_DIR}/test_it4_dco.sh"

    run_test "IT5: Multi-Client DCO (DCO-F1)" 3 \
        "${SCRIPT_DIR}/test_it5_multi_client_dco.sh"
else
    echo ""
    echo "  SKIP: IT4/IT5 (ovpn-dco module not available)"
fi

run_test "IT7: Reconnect After Disconnect" 1 \
    "${SCRIPT_DIR}/test_it7_reconnect.sh"

run_test "IT6: Masquerade / Transit Forwarding" 1 \
    "${SCRIPT_DIR}/test_it6_masquerade.sh"
# IT6 adds ns-lan-host; the test's EXIT trap removes it, but clean up just in case
ip netns del ns-lan-host 2>/dev/null || true

run_test "IT8: Netem — Latency + Loss" 1 \
    "${SCRIPT_DIR}/test_it8_netem.sh"

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Summary                                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
for r in "${RESULTS[@]}"; do
    echo "  ${r}"
done
echo ""
echo "  Passed: ${PASS}   Failed: ${FAIL}"
echo ""

if (( FAIL > 0 )); then
    echo "=== SOME TESTS FAILED ==="
    exit 1
fi

echo "=== ALL TESTS PASSED ==="
exit 0
