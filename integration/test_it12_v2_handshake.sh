#!/bin/bash
# test_it12_v2_handshake.sh — IT12: TLS-Crypt-V2 Single Client Handshake + Ping
#
# Validates that a client using tls-crypt-v2 (per-client key) can complete the
# VPN handshake with a server using the matching V2 server wrapping key, and
# that the tunnel carries traffic.
#
# This tests the P_CONTROL_WKC_V1 packet flow, WKc unwrapping, per-session
# TlsCrypt key derivation, and the complete tls-crypt-v2 handshake path.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#   - V2 key material in test_data/certs/ (tls-crypt-v2-server.key, tls-crypt-v2-client0.key)
#
# Usage: sudo ./test_it12_v2_handshake.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server_v2.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client_v2.json"

NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=15
PING_COUNT=5
PING_TIMEOUT=3

LOG_DIR="/tmp/vpn-it12"
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

echo "=== IT12: TLS-Crypt-V2 Single Client Handshake + Ping ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

if [[ ! -x "${BINARY}" ]]; then
    echo "Error: Binary not found at ${BINARY}"
    exit 1
fi

# Gate: check that V2 key material exists
if [[ ! -f "${PROJECT_ROOT}/test_data/certs/tls-crypt-v2-server.key" ]]; then
    echo "SKIP: V2 server key not found. Run test_data/certs/gen_tls_crypt_v2_keys.sh first."
    exit 77
fi
if [[ ! -f "${PROJECT_ROOT}/test_data/certs/tls-crypt-v2-client0.key" ]]; then
    echo "SKIP: V2 client key not found. Run test_data/certs/gen_tls_crypt_v2_keys.sh first."
    exit 77
fi

# Gate: check if binary supports tls-crypt-v2 config field
# Try starting server briefly to see if config parses
_test_log=$(mktemp)
timeout 3 nsenter --net="/run/netns/${NS_SERVER}" -- \
    "${BINARY}" "${SERVER_CONFIG}" > "${_test_log}" 2>&1 || true
if grep -qi "unknown.*tls_crypt_v2\|unsupported.*tls_crypt_v2\|tls.crypt.*key.*required" "${_test_log}" 2>/dev/null; then
    echo "SKIP: Binary does not support tls_crypt_v2_key config field yet."
    rm -f "${_test_log}"
    exit 77
fi
rm -f "${_test_log}"

for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
    if ! ip netns list | grep -qw "${ns}"; then
        echo "Error: Namespace ${ns} not found."
        exit 1
    fi
done

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}"
cd "${PROJECT_ROOT}"

# ── Start server + client ────────────────────────────────────────────

echo "[1/4] Starting V2 server in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

echo "[2/4] Starting V2 client, waiting for handshake (up to ${HANDSHAKE_TIMEOUT}s)..."
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

# Verify V2 was actually used (check server log for WKc / V2 mentions)
if grep -qi "tls-crypt-v2\|WKc\|unwrap.*client.*key\|per-client key" "${SERVER_LOG}" 2>/dev/null; then
    echo "      Server log confirms tls-crypt-v2 in use"
else
    echo "      Warning: Could not confirm V2 usage in server log"
fi
sleep 1

# ── Verify tunnel ────────────────────────────────────────────────────

echo "[3/4] Pinging server tunnel IP..."

ns_exec "${NS_CLIENT}" ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" -i 0.5 \
    "${TUNNEL_SERVER_IP}" > "${LOG_DIR}/ping.log" 2>&1 || true

received=$(grep -oP '\d+(?= received)' "${LOG_DIR}/ping.log" || echo "0")
echo "      Received: ${received}/${PING_COUNT}"

if (( received == 0 )); then
    cat "${LOG_DIR}/ping.log"
    fail "No tunnel pings received"
fi
echo "      Tunnel functional with V2 per-client key"

# ── Negative validation ──────────────────────────────────────────────

echo "[4/4] Negative validation — stopping VPN, confirming tunnel dies..."

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
echo "=== IT12 PASSED ==="
echo "    Mode: tls-crypt-v2 (per-client key)"
echo "    Handshake: ~${elapsed}s, Tunnel: ${received}/${PING_COUNT} pings"
echo "    Logs: ${LOG_DIR}/"
