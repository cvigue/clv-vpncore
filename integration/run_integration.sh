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
SKIP=0
XFAIL=0
XPASS=0
RESULTS=()

# ── Helpers ──────────────────────────────────────────────────────────

run_test() {
    local name="$1"
    local num_clients="$2"
    local script="$3"
    local expect_fail="${4:-0}"

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ${name}"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    # Setup
    if [[ "${num_clients}" == "mesh" ]]; then
        echo "--- Setup (mesh) ---"
        "${SCRIPT_DIR}/netns/setup_mesh.sh"
    else
        echo "--- Setup (${num_clients} client(s)) ---"
        "${SCRIPT_DIR}/netns/setup_vpn.sh" "${num_clients}"
    fi
    echo ""

    # Run
    local rc=0
    "${script}" "${PROJECT_ROOT}" || rc=$?

    # Teardown
    echo ""
    echo "--- Teardown ---"
    if [[ "${num_clients}" == "mesh" ]]; then
        "${SCRIPT_DIR}/netns/teardown_mesh.sh"
    else
        "${SCRIPT_DIR}/netns/teardown_vpn.sh" "${num_clients}"
    fi

    if (( expect_fail == 1 )); then
        if (( rc == 0 )); then
            (( XPASS++ )) || true
            RESULTS+=("XPASS ${name}")
        else
            (( XFAIL++ )) || true
            RESULTS+=("XFAIL ${name}")
        fi
    elif (( rc == 77 )); then
        (( SKIP++ )) || true
        RESULTS+=("SKIP  ${name}")
    else
        if (( rc == 0 )); then
            (( PASS++ )) || true
            RESULTS+=("PASS  ${name}")
        else
            (( FAIL++ )) || true
            RESULTS+=("FAIL  ${name}")
        fi
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

# ── Pre-flight cleanup ───────────────────────────────────────────────

# Remove any namespaces left over from a previously interrupted run.
_leftover_ns=$(ip netns list 2>/dev/null | awk '{print $1}' | grep -E '^ns-(vpn|mesh)-' || true)
if [[ -n "${_leftover_ns}" ]]; then
    echo ""
    echo "--- Pre-flight: cleaning up leftover namespaces ---"
    while IFS= read -r ns; do
        ip netns pids "${ns}" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns delete "${ns}" 2>/dev/null || true
        # Force remove stray files in /run/netns/ (in case namespace delete partially failed)
        rm -f "/run/netns/${ns}" 2>/dev/null || true
        echo "  Removed ${ns}"
    done <<< "${_leftover_ns}"
fi
ip netns del ns-lan-host 2>/dev/null || true
rm -f /run/netns/ns-lan-host 2>/dev/null || true

# ── Test execution ───────────────────────────────────────────────────

run_test "IT1: Single Client Handshake + Ping" 1 \
    "${SCRIPT_DIR}/test_it1_handshake.sh"

run_test "IT2: Multi-Client Concurrent Connect" 3 \
    "${SCRIPT_DIR}/test_it2_multi_client.sh"

run_test "IT3: Mesh Topology" mesh \
    "${SCRIPT_DIR}/test_it3_mesh.sh"

# IT4/IT5: DCO data path — skip if kernel module unavailable
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

run_test "IT8: TCP Transport — Handshake + Data" 1 \
    "${SCRIPT_DIR}/test_it8_tcp.sh"

run_test "IT19: IPv6 Underlay Connectivity (UDP client, IPv6 host)" 1 \
    "${SCRIPT_DIR}/test_it19_ipv6_underlay.sh"

run_test "IT9: client_to_client=false — Peer Isolation" 2 \
    "${SCRIPT_DIR}/test_it9_no_c2c.sh" 1

run_test "IT10: client_to_client=false — Server-Side Enforcement (route bypass)" 2 \
    "${SCRIPT_DIR}/test_it10_c2c_route_bypass.sh" 1

run_test "IT11: client_to_client=false — Full Symmetric Route Bypass" 2 \
    "${SCRIPT_DIR}/test_it11_c2c_full_bypass.sh" 1

run_test "IT12: TLS-Crypt-V2 Single Client Handshake" 1 \
    "${SCRIPT_DIR}/test_it12_v2_handshake.sh"

run_test "IT13: TLS-Crypt-V2 Multi-Client (3 distinct keys)" 3 \
    "${SCRIPT_DIR}/test_it13_v2_multi_client.sh"

# IT14/IT15: Mixed DCO/userspace mode tests — skip if kernel module unavailable
if modprobe -n ovpn-dco 2>/dev/null || modprobe -n ovpn-dco-v2 2>/dev/null; then
    run_test "IT14: Multi-Client Mixed DCO/Userspace (DCO server)" 3 \
        "${SCRIPT_DIR}/test_it14_mixed_client_dco.sh"

    run_test "IT15: Userspace Server + DCO Clients" 3 \
        "${SCRIPT_DIR}/test_it15_userspace_server_dco_clients.sh"
else
    echo ""
    echo "  SKIP: IT14/IT15 (ovpn-dco module not available)"
fi

# IT16/IT17/IT18: OpenVPN interop — skip if openvpn binary is absent
if command -v openvpn >/dev/null 2>&1; then
    run_test "IT16: OpenVPN Server + simple_vpn Client (tls-crypt v1)" 1 \
        "${SCRIPT_DIR}/test_it16_ovpn_server_handshake.sh"

    run_test "IT17: simple_vpn Server + OpenVPN Client" 1 \
        "${SCRIPT_DIR}/test_it17_ovpn_client.sh"

    run_test "IT18: OpenVPN Server + simple_vpn Client (tls-crypt-v2)" 1 \
        "${SCRIPT_DIR}/test_it18_ovpn_server_v2.sh"
else
    echo ""
    echo "  SKIP: IT16/IT17/IT18 (openvpn not installed)"
fi

# IT-R1/IT-R5: Server-initiated rekey (UDP + TCP)
run_test "IT-R1: Server-Initiated Rekey (UDP)" 1 \
    "${SCRIPT_DIR}/test_itr1_server_rekey.sh"

# IT-R2/IT-R3: Client-initiated rekey — known bug, XFAIL
run_test "IT-R2: Client-Initiated Rekey (UDP)" 1 \
    "${SCRIPT_DIR}/test_itr2_client_rekey.sh" 1

run_test "IT-R3: Two Rekey Cycles (UDP)" 1 \
    "${SCRIPT_DIR}/test_itr3_two_rekey_cycles.sh" 1

# IT-R4: DCO rekey — skip if kernel module unavailable (test itself exits 77)
run_test "IT-R4: DCO Server-Initiated Rekey" 1 \
    "${SCRIPT_DIR}/test_itr4_dco_rekey.sh"

run_test "IT-R5: Server-Initiated Rekey (TCP)" 1 \
    "${SCRIPT_DIR}/test_itr5_tcp_rekey.sh"

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Summary                                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
for r in "${RESULTS[@]}"; do
    echo "  ${r}"
done
echo ""
echo "  Passed: ${PASS}   Failed: ${FAIL}   Skipped: ${SKIP}   XFailed: ${XFAIL}   XPassed: ${XPASS}"
echo ""

if (( FAIL > 0 )); then
    echo "=== SOME TESTS FAILED ==="
    exit 1
fi

echo "=== ALL TESTS PASSED ==="
exit 0
