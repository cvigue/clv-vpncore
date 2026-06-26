#!/bin/bash
# test_it3_mesh.sh — IT3: Mesh topology with multi-role nodes
#
# Topology:
#   Node A (ns-mesh-a, 10.99.0.1): Server, tunnel 10.8.0.0/24
#   Node B (ns-mesh-b, 10.99.0.2): Server (10.9.0.0/24) + Client of A
#   Node C (ns-mesh-c, 10.99.0.3): Client of A + Client of B
#   Node D (ns-mesh-d, 10.99.0.4): Client of B
#
# Test categories:
#   [1]   Multi-role startup (server + client in one process)
#   [2]   Multi-client startup (2 connections in one process)
#   [3-6] Direct tunnel ping (each server from its clients)
#   [7]   Client-to-client through Server A (B ↔ C)
#   [8]   Client-to-client through Server B (C ↔ D)
#   [9]   Transit: D → Server A tunnel (10.8.0.1) through B
#          (B's server pushes 10.8.0.0/24 route; kernel forwards between TUNs)
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Mesh namespaces: sudo integration/netns/setup_mesh.sh
#
# Usage: sudo ./test_it3_mesh.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"
CONFIG_DIR="${PROJECT_ROOT}/integration/configs"

HANDSHAKE_TIMEOUT=25
PING_COUNT=3
PING_TIMEOUT=3

SERVER_A_TUNNEL="10.8.0.1"
SERVER_B_TUNNEL="10.9.0.1"

LOG_DIR="/tmp/vpn-it3"

PASS=0
FAIL=0
TOTAL=0
EXPECTED_FAIL=0

declare -A NODE_PIDS=()

# ── Helpers ──────────────────────────────────────────────────────────

ns_exec() { ip netns exec "$1" "${@:2}"; }

# Background variant: exec ensures $! == actual process PID (no intermediate fork)
ns_bg() { exec nsenter --net="/run/netns/$1" -- "${@:2}"; }

ns_ping() {
    ip netns exec "$1" ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" -q "$2" &>/dev/null
}

step_pass() {
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
    echo "      $1: OK"
}

step_fail() {
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
    echo "      $1: FAIL"
}

step_xfail() {
    # Expected failure — record but don't count against pass rate
    EXPECTED_FAIL=$((EXPECTED_FAIL + 1))
    TOTAL=$((TOTAL + 1))
    echo "      $1: XFAIL (expected — not yet implemented)"
}

wait_for_pattern() {
    local log_file="$1"
    local pattern="$2"
    local timeout="$3"
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if grep -q "$pattern" "$log_file" 2>/dev/null; then
            echo "$elapsed"
            return 0
        fi
        sleep 1
        ((elapsed++))
    done
    return 1
}

# Get all tunnel IPs assigned within a namespace (across all tun* devices)
get_tunnel_ips() {
    local ns="$1"
    ip netns exec "$ns" ip -4 addr show 2>/dev/null \
        | grep -E 'inet .* (tun|ovpn)' \
        | grep -oP 'inet \K\S+' \
        | sed 's|/.*||' || true
}

# Get the tunnel IP that falls within a specific subnet
get_tunnel_ip_in_subnet() {
    local ns="$1"
    local subnet_prefix="$2"  # e.g., "10.8.0." or "10.9.0."
    get_tunnel_ips "$ns" | grep "^${subnet_prefix}" | head -1
}

dump_logs() {
    for node in a b c d; do
        echo ""
        echo "--- Node ${node} log (last 40 lines) ---"
        tail -40 "${LOG_DIR}/node-${node}.log" 2>/dev/null || echo "(no log)"
    done
}

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    for node in a b c d; do
        local pid="${NODE_PIDS[$node]:-}"
        [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 1
    for node in a b c d; do
        local pid="${NODE_PIDS[$node]:-}"
        [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT

# ── Preconditions ────────────────────────────────────────────────────

echo "=== IT3: Mesh Topology (4 nodes, multi-role) ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

if [[ ! -x "${BINARY}" ]]; then
    echo "Error: Binary not found at ${BINARY}"
    echo "       Run 'ninja -C build' first."
    exit 1
fi

for node in a b c d; do
    ns="ns-mesh-${node}"
    if ! ip netns list | grep -qw "${ns}"; then
        echo "Error: Namespace ${ns} not found."
        echo "       Run 'sudo integration/netns/setup_mesh.sh' first."
        exit 1
    fi
done

rm -rf "${LOG_DIR}"
mkdir -p "${LOG_DIR}"

# Cert paths are relative to project root
cd "${PROJECT_ROOT}"

# ── [1/9] Start servers (A and B) ───────────────────────────────────

echo "[1/9] Starting Server A (pure server) and Server B (server + client of A)..."

ns_bg ns-mesh-a "${BINARY}" "${CONFIG_DIR}/mesh_node_a.json" \
    > "${LOG_DIR}/node-a.log" 2>&1 &
NODE_PIDS[a]=$!

# Brief pause so A is listening before B's client tries to connect
sleep 2

ns_bg ns-mesh-b "${BINARY}" "${CONFIG_DIR}/mesh_node_b.json" \
    > "${LOG_DIR}/node-b.log" 2>&1 &
NODE_PIDS[b]=$!

echo "      Node A PID: ${NODE_PIDS[a]} (ns-mesh-a, pure server)"
echo "      Node B PID: ${NODE_PIDS[b]} (ns-mesh-b, server + client)"

# Wait for A to be listening
if ! wait_for_pattern "${LOG_DIR}/node-a.log" "Server listening" "${HANDSHAKE_TIMEOUT}" >/dev/null; then
    echo "FAIL: Server A did not start"
    dump_logs
    exit 1
fi

# Wait for B's server to start AND B's client to connect to A
if ! wait_for_pattern "${LOG_DIR}/node-b.log" "Server listening" "${HANDSHAKE_TIMEOUT}" >/dev/null; then
    echo "FAIL: Server B did not start"
    dump_logs
    exit 1
fi

if ! wait_for_pattern "${LOG_DIR}/node-b.log" "Client 1 connected" "${HANDSHAKE_TIMEOUT}" >/dev/null; then
    echo "FAIL: Node B's client did not connect to Server A"
    dump_logs
    exit 1
fi

echo "      Node B: server up + client connected to A"

# ── [2/9] Start clients (C and D) ───────────────────────────────────

echo "[2/9] Starting Node C (client of A + B) and Node D (client of B)..."

ns_bg ns-mesh-c "${BINARY}" "${CONFIG_DIR}/mesh_node_c.json" \
    > "${LOG_DIR}/node-c.log" 2>&1 &
NODE_PIDS[c]=$!

ns_bg ns-mesh-d "${BINARY}" "${CONFIG_DIR}/mesh_node_d.json" \
    > "${LOG_DIR}/node-d.log" 2>&1 &
NODE_PIDS[d]=$!

echo "      Node C PID: ${NODE_PIDS[c]} (ns-mesh-c, 2 clients)"
echo "      Node D PID: ${NODE_PIDS[d]} (ns-mesh-d, 1 client)"

# Wait for C's two clients to connect
if ! wait_for_pattern "${LOG_DIR}/node-c.log" "Client 1 connected" "${HANDSHAKE_TIMEOUT}" >/dev/null; then
    echo "FAIL: Node C client 1 did not connect to Server A"
    dump_logs
    exit 1
fi
if ! wait_for_pattern "${LOG_DIR}/node-c.log" "Client 2 connected" "${HANDSHAKE_TIMEOUT}" >/dev/null; then
    echo "FAIL: Node C client 2 did not connect to Server B"
    dump_logs
    exit 1
fi
echo "      Node C: both clients connected"

# Wait for D to connect to B
if ! wait_for_pattern "${LOG_DIR}/node-d.log" "Client connected" "${HANDSHAKE_TIMEOUT}" >/dev/null; then
    echo "FAIL: Node D did not connect to Server B"
    dump_logs
    exit 1
fi
echo "      Node D: client connected to B"

# Allow routes to settle
sleep 2

# ── [3/9] Direct ping: B → Server A tunnel ──────────────────────────

echo "[3/9] Direct tunnel pings..."

if ns_ping ns-mesh-b "${SERVER_A_TUNNEL}"; then
    step_pass "B → A tunnel (${SERVER_A_TUNNEL})"
else
    step_fail "B → A tunnel (${SERVER_A_TUNNEL})"
fi

# ── [4/9] Direct ping: C → Server A tunnel ──────────────────────────

if ns_ping ns-mesh-c "${SERVER_A_TUNNEL}"; then
    step_pass "C → A tunnel (${SERVER_A_TUNNEL})"
else
    step_fail "C → A tunnel (${SERVER_A_TUNNEL})"
fi

# ── [5/9] Direct ping: C → Server B tunnel ──────────────────────────

if ns_ping ns-mesh-c "${SERVER_B_TUNNEL}"; then
    step_pass "C → B tunnel (${SERVER_B_TUNNEL})"
else
    step_fail "C → B tunnel (${SERVER_B_TUNNEL})"
fi

# ── [6/9] Direct ping: D → Server B tunnel ──────────────────────────

if ns_ping ns-mesh-d "${SERVER_B_TUNNEL}"; then
    step_pass "D → B tunnel (${SERVER_B_TUNNEL})"
else
    step_fail "D → B tunnel (${SERVER_B_TUNNEL})"
fi

# ── [7/9] Client-to-client through A: B ↔ C ─────────────────────────

echo "[7/9] Client-to-client through Server A (B ↔ C)..."

B_IP_A=$(get_tunnel_ip_in_subnet ns-mesh-b "10.8.0.")
C_IP_A=$(get_tunnel_ip_in_subnet ns-mesh-c "10.8.0.")

if [[ -z "$B_IP_A" ]]; then
    step_fail "B has no tunnel IP in 10.8.0.0/24"
elif [[ -z "$C_IP_A" ]]; then
    step_fail "C has no tunnel IP in 10.8.0.0/24"
else
    echo "      B tunnel IP (A's subnet): ${B_IP_A}"
    echo "      C tunnel IP (A's subnet): ${C_IP_A}"

    c2c_pass=0
    c2c_total=0

    if ns_ping ns-mesh-b "${C_IP_A}"; then c2c_pass=$((c2c_pass + 1)); fi
    c2c_total=$((c2c_total + 1))
    if ns_ping ns-mesh-c "${B_IP_A}"; then c2c_pass=$((c2c_pass + 1)); fi
    c2c_total=$((c2c_total + 1))

    if [[ $c2c_pass -eq $c2c_total ]]; then
        step_pass "B ↔ C through A (${c2c_pass}/${c2c_total})"
    else
        step_fail "B ↔ C through A (${c2c_pass}/${c2c_total})"
    fi
fi

# ── [8/9] Client-to-client through B: C ↔ D ─────────────────────────

echo "[8/9] Client-to-client through Server B (C ↔ D)..."

C_IP_B=$(get_tunnel_ip_in_subnet ns-mesh-c "10.9.0.")
D_IP_B=$(get_tunnel_ip_in_subnet ns-mesh-d "10.9.0.")

if [[ -z "$C_IP_B" ]]; then
    step_fail "C has no tunnel IP in 10.9.0.0/24"
elif [[ -z "$D_IP_B" ]]; then
    step_fail "D has no tunnel IP in 10.9.0.0/24"
else
    echo "      C tunnel IP (B's subnet): ${C_IP_B}"
    echo "      D tunnel IP (B's subnet): ${D_IP_B}"

    c2c_pass=0
    c2c_total=0

    if ns_ping ns-mesh-c "${D_IP_B}"; then c2c_pass=$((c2c_pass + 1)); fi
    c2c_total=$((c2c_total + 1))
    if ns_ping ns-mesh-d "${C_IP_B}"; then c2c_pass=$((c2c_pass + 1)); fi
    c2c_total=$((c2c_total + 1))

    if [[ $c2c_pass -eq $c2c_total ]]; then
        step_pass "C ↔ D through B (${c2c_pass}/${c2c_total})"
    else
        step_fail "C ↔ D through B (${c2c_pass}/${c2c_total})"
    fi
fi

# ── [9/9] Transit: D → Server A tunnel through B ────────────────────

echo "[9/9] Transit routing: D → Server A tunnel (${SERVER_A_TUNNEL}) through B..."
echo "      (B forwards between its server TUN and client-of-A TUN via kernel ip_forward)"

if ns_ping ns-mesh-d "${SERVER_A_TUNNEL}"; then
    step_pass "D → A tunnel through B (transit)"
else
    step_fail "D → A tunnel through B (transit)"
fi

# ── [10] Negative validation: tunnel requires VPN ────────────────────

echo "[10] Negative validation — stopping all VPN processes, confirming tunnels die..."

# Kill VPN processes
for node in a b c d; do
    pid="${NODE_PIDS[$node]:-}"
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
done
sleep 2
for node in a b c d; do
    pid="${NODE_PIDS[$node]:-}"
    [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
done
wait 2>/dev/null || true
# Clear PIDs so cleanup trap doesn't re-kill
for node in a b c d; do
    NODE_PIDS[$node]=""
done

# Remove TUN devices — persistent TUNs survive process death, so
# explicitly delete them to prove the tunnel was the only route.
for ns in ns-mesh-a ns-mesh-b ns-mesh-c ns-mesh-d; do
    for dev in $(ip netns exec "$ns" ip -o link show type tun 2>/dev/null | awk -F: '{print $2}' | tr -d ' '); do
        ip netns exec "$ns" ip link del "$dev" 2>/dev/null || true
    done
done

neg_ok=1
# B should no longer reach A's tunnel
if ns_ping ns-mesh-b "${SERVER_A_TUNNEL}"; then
    echo "      B → A tunnel: still reachable (BAD)"
    neg_ok=0
else
    echo "      B → A tunnel: unreachable (good)"
fi
# D should no longer reach B's tunnel
if ns_ping ns-mesh-d "${SERVER_B_TUNNEL}"; then
    echo "      D → B tunnel: still reachable (BAD)"
    neg_ok=0
else
    echo "      D → B tunnel: unreachable (good)"
fi

if (( neg_ok == 0 )); then
    step_fail "Tunnel reachable after VPN stopped — traffic may not be using the tunnel"
else
    step_pass "Tunnels correctly unreachable after VPN stopped"
fi

# ── Summary ──────────────────────────────────────────────────────────

echo ""
if [[ $FAIL -eq 0 ]]; then
    echo "=== IT3 PASSED ==="
else
    echo "=== IT3 FAILED ==="
fi
echo "    ${PASS} passed, ${FAIL} failed, ${EXPECTED_FAIL} expected-fail (${TOTAL} total)"
echo "    Logs: ${LOG_DIR}/"

if [[ $FAIL -gt 0 ]]; then
    dump_logs
    exit 1
fi
exit 0
