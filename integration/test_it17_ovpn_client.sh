#!/bin/bash
# test_it17_ovpn_client.sh — IT17: simple_vpn server + openvpn client
#
# Interoperability test: our simple_vpn server receives a connection from the
# reference OpenVPN implementation acting as client.
#
# Validates:
#   Server-side robustness to openvpn's richer IV_PROTO bitmask and peer-info
#   PUSH_REPLY delivery to a real openvpn client • data channel • tunnel ping
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - openvpn >= 2.6 installed (skips with exit 77 if absent)
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#
# Usage: sudo ./test_it17_ovpn_client.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server.json"
OVPN_CLIENT_CONF="${SCRIPT_DIR}/configs/openvpn/it17_client.conf"

NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"

TUNNEL_SERVER_IP="10.8.0.1"
SERVER_START_WAIT=2          # seconds before starting client after server launches
HANDSHAKE_TIMEOUT=20         # seconds to wait for openvpn "Initialization..."
PING_COUNT=5
PING_TIMEOUT=3

LOG_DIR="/tmp/vpn-it17"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"

SERVER_PID=""
CLIENT_PID=""

# ── Helpers ──────────────────────────────────────────────────────────

ns_exec() { ip netns exec "$1" "${@:2}"; }
ns_bg()   { exec nsenter --net="/run/netns/$1" -- "${@:2}"; }

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

echo "=== IT17: simple_vpn Server + OpenVPN Client — Interop Handshake ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

if ! command -v openvpn >/dev/null 2>&1; then
    echo "SKIP: openvpn not found on PATH"
    exit 77
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
rm -f "${SERVER_LOG}" "${CLIENT_LOG}"

cd "${PROJECT_ROOT}"

# ── Start simple_vpn server ───────────────────────────────────────────

echo "[1/6] Starting simple_vpn server in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep "${SERVER_START_WAIT}"

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "simple_vpn server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

# ── Start openvpn client ──────────────────────────────────────────────

echo "[2/6] Starting openvpn client in ${NS_CLIENT}..."
ns_bg "${NS_CLIENT}" openvpn \
    --cd "${PROJECT_ROOT}" \
    --config "${OVPN_CLIENT_CONF}" \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!
echo "      Client PID: ${CLIENT_PID}"

# ── Wait for openvpn to complete TLS + data channel setup ────────────

echo "[3/6] Waiting up to ${HANDSHAKE_TIMEOUT}s for openvpn to connect..."

handshake_ok=0
elapsed=0
while (( elapsed < HANDSHAKE_TIMEOUT )); do
    if grep -q "Initialization Sequence Completed" "${CLIENT_LOG}" 2>/dev/null; then
        handshake_ok=1
        break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        fail "simple_vpn server died during handshake"
    fi
    if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
        fail "openvpn client died during handshake"
    fi
    sleep 1
    (( elapsed++ )) || true
done

if (( handshake_ok == 0 )); then
    fail "openvpn did not report 'Initialization Sequence Completed' within ${HANDSHAKE_TIMEOUT}s"
fi
echo "      Handshake completed in ~${elapsed}s"

# ── Ping through tunnel ─────────────────────────────────────────────

echo "[4/6] Pinging server tunnel IP ${TUNNEL_SERVER_IP} from openvpn client..."
sleep 1

if ns_exec "${NS_CLIENT}" ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" \
    "${TUNNEL_SERVER_IP}" > "${LOG_DIR}/ping.log" 2>&1; then
    echo "      Ping successful (${PING_COUNT}/${PING_COUNT})"
else
    received=$(grep -oP '\d+(?= received)' "${LOG_DIR}/ping.log" || echo "0")
    if (( received > 0 )); then
        echo "      Partial ping success (${received}/${PING_COUNT})"
    else
        fail "Tunnel ping failed — no packets received"
    fi
fi

# ── Collect results ──────────────────────────────────────────────────

echo "[5/6] Collecting results..."
echo ""
echo "--- Ping Results ---"
cat "${LOG_DIR}/ping.log"

# ── Negative validation ─────────────────────────────────────────────

echo ""
echo "[6/6] Negative validation — stopping VPN, confirming tunnel dies..."

kill -TERM "${CLIENT_PID}" 2>/dev/null || true
kill -TERM "${SERVER_PID}" 2>/dev/null || true
sleep 2
kill -9 "${CLIENT_PID}" 2>/dev/null || true
kill -9 "${SERVER_PID}" 2>/dev/null || true
wait 2>/dev/null || true
CLIENT_PID=""
SERVER_PID=""

for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
    for dev in $(ns_exec "$ns" ip -o link show type tun 2>/dev/null | awk -F: '{print $2}' | tr -d ' '); do
        ns_exec "$ns" ip link del "$dev" 2>/dev/null || true
    done
done

if ns_exec "${NS_CLIENT}" ping -c 1 -W 2 "${TUNNEL_SERVER_IP}" &>/dev/null; then
    fail "Tunnel ping succeeded after VPN stopped — traffic may not be using the tunnel"
else
    echo "      Tunnel ping correctly failed after VPN stopped"
fi

echo ""
echo "=== IT17 PASSED ==="
echo "    Logs: ${LOG_DIR}/"
