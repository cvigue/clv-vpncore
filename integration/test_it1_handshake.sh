#!/bin/bash
# test_it1_handshake.sh — IT1: Single client handshake + tunnel ping
#
# Validates the full VPN stack end-to-end:
#   TLS handshake → TLS-Crypt → PUSH_REPLY → data channel → TUN routing
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#
# Usage: sudo ./test_it1_handshake.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client.json"

NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=15        # seconds to wait for handshake
PING_COUNT=5
PING_TIMEOUT=3              # per-ping deadline

# Log locations
LOG_DIR="/tmp/vpn-it1"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"

SERVER_PID=""
CLIENT_PID=""

# ── Helpers ──────────────────────────────────────────────────────────

ns_exec() { ip netns exec "$1" "${@:2}"; }

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    [[ -n "${CLIENT_PID}" ]] && kill -TERM "${CLIENT_PID}" 2>/dev/null || true
    [[ -n "${SERVER_PID}" ]] && kill -TERM "${SERVER_PID}" 2>/dev/null || true
    sleep 1
    [[ -n "${CLIENT_PID}" ]] && kill -9 "${CLIENT_PID}" 2>/dev/null || true
    [[ -n "${SERVER_PID}" ]] && kill -9 "${SERVER_PID}" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    echo ""
    echo "--- Server log (last 40 lines) ---"
    tail -40 "${SERVER_LOG}" 2>/dev/null || echo "(no log)"
    echo ""
    echo "--- Client log (last 40 lines) ---"
    tail -40 "${CLIENT_LOG}" 2>/dev/null || echo "(no log)"
    exit 1
}

# ── Preconditions ────────────────────────────────────────────────────

echo "=== IT1: Single Client Handshake + Ping ==="

# Escalate to root if not already (supports direct invocation)
if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

if [[ ! -x "${BINARY}" ]]; then
    echo "Error: Binary not found at ${BINARY}"
    echo "       Run 'ninja -C build' first."
    exit 1
fi

# Verify namespaces exist
for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
    if ! ip netns list | grep -qw "${ns}"; then
        echo "Error: Namespace ${ns} not found."
        echo "       Run 'sudo integration/netns/setup_vpn.sh 1' first."
        exit 1
    fi
done

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}"

# Ensure relative paths in configs (test_data/certs/...) resolve correctly
cd "${PROJECT_ROOT}"

# ── Start server ─────────────────────────────────────────────────────

echo "[1/5] Starting server in ${NS_SERVER}..."
ns_exec "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

# ── Start client ─────────────────────────────────────────────────────

echo "[2/5] Starting client in ${NS_CLIENT}..."
ns_exec "${NS_CLIENT}" "${BINARY}" "${CLIENT_CONFIG}" \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!
echo "      Client PID: ${CLIENT_PID}"

# ── Wait for handshake ───────────────────────────────────────────────

echo "[3/5] Waiting up to ${HANDSHAKE_TIMEOUT}s for handshake..."

handshake_ok=0
elapsed=0
while (( elapsed < HANDSHAKE_TIMEOUT )); do
    # Check client log for "Connected" state transition
    if grep -qi "client connected\|state.*connected\|connected to server\|PUSH_REPLY.*received\|tunnel established" \
         "${CLIENT_LOG}" 2>/dev/null; then
        handshake_ok=1
        break
    fi
    # Check if either process died
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

# ── Ping through tunnel ─────────────────────────────────────────────

echo "[4/5] Pinging tunnel gateway ${TUNNEL_SERVER_IP} from client..."

# Small settle time for routes to install
sleep 1

if ns_exec "${NS_CLIENT}" ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" \
    "${TUNNEL_SERVER_IP}" > "${LOG_DIR}/ping.log" 2>&1; then
    echo "      Ping successful (${PING_COUNT}/${PING_COUNT})"
else
    # Check partial success
    received=$(grep -oP '\d+(?= received)' "${LOG_DIR}/ping.log" || echo "0")
    if (( received > 0 )); then
        echo "      Partial ping success (${received}/${PING_COUNT})"
    else
        fail "Tunnel ping failed — no packets received"
    fi
fi

# ── Collect results ──────────────────────────────────────────────────

echo "[5/5] Collecting results..."
echo ""
echo "--- Ping Results ---"
cat "${LOG_DIR}/ping.log"

echo ""
echo "=== IT1 PASSED ==="
echo "    Logs: ${LOG_DIR}/"
