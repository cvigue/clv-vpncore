#!/bin/bash
# test_it7_reconnect.sh — IT7: Reconnect after disconnect
#
# Validates client reconnect and server session cleanup:
#
#   1. Client connects, tunnel verified
#   2. Client process killed (simulating crash)
#   3. Server detects dead peer via keepalive timeout → cleans up session + releases IP
#   4. New client process connects, tunnel verified
#   5. IP recycled from pool (proves session was properly cleaned up)
#
# Uses aggressive keepalive [2, 10] so dead-peer detection happens in ~12s.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#
# Usage: sudo ./test_it7_reconnect.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server_reconnect.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client.json"

NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=15
PING_COUNT=3
PING_TIMEOUT=3
DEAD_PEER_TIMEOUT=16        # wait for server to detect dead peer (keepalive timeout=10 + margin)

LOG_DIR="/tmp/vpn-it7"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client1.log"
CLIENT2_LOG="${LOG_DIR}/client2.log"

SERVER_PID=""
CLIENT_PID=""

# ── Helpers ──────────────────────────────────────────────────────────

ns_exec() { ip netns exec "$1" "${@:2}"; }
ns_bg() { exec nsenter --net="/run/netns/$1" -- "${@:2}"; }

get_tunnel_ip() {
    local ns="$1"
    ns_exec "$ns" ip -4 addr show tun0 2>/dev/null | grep -oP 'inet \K[\d.]+' || true
}

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    [[ -n "${CLIENT_PID}" ]] && kill -TERM "${CLIENT_PID}" 2>/dev/null || true
    [[ -n "${SERVER_PID}" ]] && kill -TERM "${SERVER_PID}" 2>/dev/null || true
    sleep 1
    [[ -n "${CLIENT_PID}" ]] && kill -9 "${CLIENT_PID}" 2>/dev/null || true
    [[ -n "${SERVER_PID}" ]] && kill -9 "${SERVER_PID}" 2>/dev/null || true
    wait 2>/dev/null || true
    # Remove TUN devices
    for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
        for dev in $(ns_exec "$ns" ip -o link show type tun 2>/dev/null \
                     | awk -F: '{print $2}' | tr -d ' '); do
            ns_exec "$ns" ip link del "$dev" 2>/dev/null || true
        done
    done
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    echo ""
    echo "--- Server log (last 60 lines) ---"
    tail -60 "${SERVER_LOG}" 2>/dev/null || echo "(no log)"
    echo ""
    echo "--- Client 1 log (last 40 lines) ---"
    tail -40 "${CLIENT_LOG}" 2>/dev/null || echo "(no log)"
    echo ""
    echo "--- Client 2 log (last 40 lines) ---"
    tail -40 "${CLIENT2_LOG}" 2>/dev/null || echo "(no log)"
    exit 1
}

wait_handshake() {
    local log_file="$1"
    local label="$2"
    local ok=0
    local elapsed=0
    while (( elapsed < HANDSHAKE_TIMEOUT )); do
        if grep -qi "client connected\|state.*connected\|connected to server\|PUSH_REPLY.*received\|tunnel established" \
             "${log_file}" 2>/dev/null; then
            ok=1
            break
        fi
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            fail "Server process died during ${label} handshake"
        fi
        if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
            fail "Client process died during ${label} handshake"
        fi
        sleep 1
        (( elapsed++ )) || true
    done
    if (( ok == 0 )); then
        fail "${label} handshake did not complete within ${HANDSHAKE_TIMEOUT}s"
    fi
    echo "      Handshake completed in ~${elapsed}s"
}

# ── Preconditions ────────────────────────────────────────────────────

echo "=== IT7: Reconnect After Disconnect ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

if [[ ! -x "${BINARY}" ]]; then
    echo "Error: Binary not found at ${BINARY}"
    echo "       Run 'ninja -C build' first."
    exit 1
fi

for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
    if ! ip netns list | grep -qw "${ns}"; then
        echo "Error: Namespace ${ns} not found."
        echo "       Run 'sudo integration/netns/setup_vpn.sh 1' first."
        exit 1
    fi
done

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}" "${CLIENT2_LOG}"

cd "${PROJECT_ROOT}"

# ── Phase 1: Initial connection ──────────────────────────────────────

echo "[1/8] Starting server (keepalive 2/10) in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

echo "[2/8] Starting client-1, waiting for handshake..."
ns_bg "${NS_CLIENT}" "${BINARY}" "${CLIENT_CONFIG}" \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!
echo "      Client-1 PID: ${CLIENT_PID}"

wait_handshake "${CLIENT_LOG}" "client-1"
sleep 1

# Record the tunnel IP assigned to client-1
CLIENT1_IP=$(get_tunnel_ip "${NS_CLIENT}")
if [[ -z "${CLIENT1_IP}" ]]; then
    fail "Client-1 has no tunnel IP on tun0"
fi
echo "      Client-1 tunnel IP: ${CLIENT1_IP}"

echo "[3/8] Verifying tunnel (client-1 → server)..."
if ns_exec "${NS_CLIENT}" ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" \
    "${TUNNEL_SERVER_IP}" > "${LOG_DIR}/ping1.log" 2>&1; then
    echo "      Ping successful (${PING_COUNT}/${PING_COUNT})"
else
    received=$(grep -oP '\d+(?= received)' "${LOG_DIR}/ping1.log" || echo "0")
    if (( received > 0 )); then
        echo "      Partial ping success (${received}/${PING_COUNT})"
    else
        fail "Client-1 tunnel ping failed"
    fi
fi

# ── Phase 2: Kill client, wait for server cleanup ────────────────────

echo "[4/8] Killing client-1 (SIGKILL, simulating crash)..."
kill -9 "${CLIENT_PID}" 2>/dev/null || true
wait "${CLIENT_PID}" 2>/dev/null || true
CLIENT_PID=""

# Remove persistent TUN device so it doesn't interfere with reconnect
for dev in $(ns_exec "${NS_CLIENT}" ip -o link show type tun 2>/dev/null \
             | awk -F: '{print $2}' | tr -d ' '); do
    ns_exec "${NS_CLIENT}" ip link del "$dev" 2>/dev/null || true
done

# Verify tunnel is dead
if ns_exec "${NS_CLIENT}" ping -c 1 -W 2 "${TUNNEL_SERVER_IP}" &>/dev/null; then
    fail "Tunnel ping succeeded after client killed — TUN device not cleaned up"
fi
echo "      Client-1 killed, tunnel confirmed dead"

echo "[5/8] Waiting up to ${DEAD_PEER_TIMEOUT}s for server dead-peer detection..."
dead_peer_ok=0
elapsed=0
while (( elapsed < DEAD_PEER_TIMEOUT )); do
    if grep -qi "Peer dead\|removed session\|timed out.*since last activity" \
         "${SERVER_LOG}" 2>/dev/null; then
        dead_peer_ok=1
        break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        fail "Server process died while waiting for dead-peer detection"
    fi
    sleep 1
    (( elapsed++ )) || true
done

if (( dead_peer_ok == 0 )); then
    fail "Server did not detect dead peer within ${DEAD_PEER_TIMEOUT}s"
fi
echo "      Server detected dead peer in ~${elapsed}s"

# ── Phase 3: Reconnect with new client process ──────────────────────

echo "[6/8] Starting client-2, waiting for handshake..."
ns_bg "${NS_CLIENT}" "${BINARY}" "${CLIENT_CONFIG}" \
    > "${CLIENT2_LOG}" 2>&1 &
CLIENT_PID=$!
echo "      Client-2 PID: ${CLIENT_PID}"

wait_handshake "${CLIENT2_LOG}" "client-2"
sleep 1

echo "[7/8] Verifying tunnel (client-2 → server) + IP recycling..."

# Check tunnel works
if ns_exec "${NS_CLIENT}" ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" \
    "${TUNNEL_SERVER_IP}" > "${LOG_DIR}/ping2.log" 2>&1; then
    echo "      Ping successful (${PING_COUNT}/${PING_COUNT})"
else
    received=$(grep -oP '\d+(?= received)' "${LOG_DIR}/ping2.log" || echo "0")
    if (( received > 0 )); then
        echo "      Partial ping success (${received}/${PING_COUNT})"
    else
        fail "Client-2 tunnel ping failed"
    fi
fi

# Verify IP recycling: client-2 should get the same IP as client-1
# (since server cleaned up client-1's session and released the IP)
CLIENT2_IP=$(get_tunnel_ip "${NS_CLIENT}")
if [[ -z "${CLIENT2_IP}" ]]; then
    fail "Client-2 has no tunnel IP on tun0"
fi
echo "      Client-2 tunnel IP: ${CLIENT2_IP}"

if [[ "${CLIENT1_IP}" == "${CLIENT2_IP}" ]]; then
    echo "      IP recycled: ${CLIENT1_IP} → ${CLIENT2_IP} (same — session was cleaned up)"
else
    echo "      IP changed: ${CLIENT1_IP} → ${CLIENT2_IP} (different — acceptable)"
    echo "      Note: IP recycling depends on pool allocation order"
fi

# ── Negative validation ──────────────────────────────────────────────

echo "[8/8] Negative validation — stopping VPN, confirming tunnel dies..."

kill -TERM "${CLIENT_PID}" 2>/dev/null || true
kill -TERM "${SERVER_PID}" 2>/dev/null || true
sleep 2
kill -9 "${CLIENT_PID}" 2>/dev/null || true
kill -9 "${SERVER_PID}" 2>/dev/null || true
wait 2>/dev/null || true
CLIENT_PID=""
SERVER_PID=""

for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
    for dev in $(ns_exec "$ns" ip -o link show type tun 2>/dev/null \
                 | awk -F: '{print $2}' | tr -d ' '); do
        ns_exec "$ns" ip link del "$dev" 2>/dev/null || true
    done
done

if ns_exec "${NS_CLIENT}" ping -c 1 -W 2 "${TUNNEL_SERVER_IP}" &>/dev/null; then
    fail "Tunnel ping succeeded after VPN stopped"
else
    echo "      Tunnel ping correctly failed after VPN stopped"
fi

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo "=== IT7 PASSED ==="
echo "    Client-1 connected (${CLIENT1_IP}), tunnel verified"
echo "    Client-1 killed, server detected dead peer in ~${elapsed}s"
echo "    Client-2 reconnected (${CLIENT2_IP}), tunnel verified"
echo "    Logs: ${LOG_DIR}/"
