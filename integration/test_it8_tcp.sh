#!/bin/bash
# test_it8_tcp.sh — IT8: TCP Transport — Handshake + Data
#
# Validates that VPN handshake and tunnel work correctly over TCP transport
# instead of the default UDP. Tests the OpenVPN length-prefix framing and
# TCP-specific code paths in both server and client.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#
# Usage: sudo ./test_it8_tcp.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server_tcp.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client_tcp.json"

NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=15
PING_COUNT=10
PING_TIMEOUT=3

LOG_DIR="/tmp/vpn-it8"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"

SERVER_PID=""
CLIENT_PID=""

# ── Helpers ──────────────────────────────────────────────────────────

ns_exec() { ip netns exec "$1" "${@:2}"; }
ns_bg() { exec nsenter --net="/run/netns/$1" -- "${@:2}"; }

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
    echo "--- Server log (last 50 lines) ---"
    tail -50 "${SERVER_LOG}" 2>/dev/null || echo "(no log)"
    echo ""
    echo "--- Client log (last 50 lines) ---"
    tail -50 "${CLIENT_LOG}" 2>/dev/null || echo "(no log)"
    exit 1
}

# ── Preconditions ────────────────────────────────────────────────────

echo "=== IT8: TCP Transport — Handshake + Data ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

if [[ ! -x "${BINARY}" ]]; then
    echo "Error: Binary not found at ${BINARY}"
    exit 1
fi

for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
    if ! ip netns list | grep -qw "${ns}"; then
        echo "Error: Namespace ${ns} not found."
        exit 1
    fi
done

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}"
cd "${PROJECT_ROOT}"

# ── Verify TCP connectivity on underlay ──────────────────────────────

echo "[1/5] Verifying underlay connectivity..."
if ! ns_exec "${NS_CLIENT}" ping -c 1 -W 2 10.99.0.1 &>/dev/null; then
    fail "Cannot reach server on underlay (10.99.0.1)"
fi
echo "      Underlay OK"

# ── Start server + client ────────────────────────────────────────────

echo "[2/5] Starting TCP server in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

# Verify server is listening on TCP
if ! ns_exec "${NS_SERVER}" ss -tlnp | grep -q ":1194 "; then
    echo "      Warning: TCP listener not detected on :1194 (may still be starting)"
fi

echo "[3/5] Starting TCP client, waiting for handshake (up to ${HANDSHAKE_TIMEOUT}s)..."
ns_bg "${NS_CLIENT}" "${BINARY}" "${CLIENT_CONFIG}" \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!

handshake_ok=0
elapsed=0
while (( elapsed < HANDSHAKE_TIMEOUT )); do
    if grep -qi "client connected\|state.*connected\|connected to server\|PUSH_REPLY.*received\|tunnel established" \
         "${CLIENT_LOG}" 2>/dev/null; then
        handshake_ok=1
        break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        fail "Server process died during handshake"
    fi
    if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
        fail "Client process died during handshake"
    fi
    sleep 1
    (( elapsed++ )) || true
done

if (( handshake_ok == 0 )); then
    fail "Handshake did not complete within ${HANDSHAKE_TIMEOUT}s"
fi
echo "      Handshake completed in ~${elapsed}s"
sleep 1

# ── Verify tunnel ────────────────────────────────────────────────────

echo "[4/5] Pinging server tunnel IP (${PING_COUNT} packets over TCP transport)..."

ns_exec "${NS_CLIENT}" ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" -i 0.2 \
    "${TUNNEL_SERVER_IP}" > "${LOG_DIR}/ping.log" 2>&1 || true

received=$(grep -oP '\d+(?= received)' "${LOG_DIR}/ping.log" || echo "0")
echo "      Received: ${received}/${PING_COUNT}"

if (( received < PING_COUNT )); then
    echo ""
    cat "${LOG_DIR}/ping.log"
    fail "Tunnel ping loss over TCP: ${received}/${PING_COUNT} (expected 0 loss on reliable transport)"
fi
echo "      All pings received — TCP transport functional"

# ── Negative validation ──────────────────────────────────────────────

echo "[5/5] Negative validation — stopping VPN, confirming tunnel dies..."

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
    echo "      Tunnel correctly unreachable after VPN stopped"
fi

echo ""
echo "=== IT8 PASSED ==="
echo "    Transport: TCP"
echo "    Handshake: ~${elapsed}s, Tunnel: ${received}/${PING_COUNT} pings"
echo "    Logs: ${LOG_DIR}/"
