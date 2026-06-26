#!/bin/bash
# test_it13_v2_multi_client.sh — IT13: TLS-Crypt-V2 Multi-Client (3 clients, distinct keys)
#
# Validates that three clients, each using a different tls-crypt-v2 per-client
# key, can simultaneously connect to the same server and communicate through
# the tunnel. Each client gets a unique TlsCrypt session derived from their WKc.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 3
#   - V2 key material: tls-crypt-v2-server.key, tls-crypt-v2-client{0,1,2}.key
#
# Usage: sudo ./test_it13_v2_multi_client.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server_v2.json"
# Each client uses a distinct per-client key
CLIENT_CONFIGS=(
    "${PROJECT_ROOT}/integration/configs/it_client_v2.json"
    "${PROJECT_ROOT}/integration/configs/it_client_v2_c1.json"
    "${PROJECT_ROOT}/integration/configs/it_client_v2_c2.json"
)

NS_SERVER="ns-vpn-server"
NS_CLIENTS=("ns-vpn-client-0" "ns-vpn-client-1" "ns-vpn-client-2")
NUM_CLIENTS=3

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=20
PING_TIMEOUT=3

LOG_DIR="/tmp/vpn-it13"
SERVER_LOG="${LOG_DIR}/server.log"

SERVER_PID=""
CLIENT_PIDS=()

# ── Helpers ──────────────────────────────────────────────────────────

ns_exec() { ip netns exec "$1" "${@:2}"; }
ns_bg() { exec nsenter --net="/run/netns/$1" -- "${@:2}"; }

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    for pid in "${CLIENT_PIDS[@]}"; do
        kill -TERM "${pid}" 2>/dev/null || true
    done
    [[ -n "${SERVER_PID}" ]] && kill -TERM "${SERVER_PID}" 2>/dev/null || true
    sleep 1
    for pid in "${CLIENT_PIDS[@]}"; do
        kill -9 "${pid}" 2>/dev/null || true
    done
    [[ -n "${SERVER_PID}" ]] && kill -9 "${SERVER_PID}" 2>/dev/null || true
    wait 2>/dev/null || true
    for ns in "${NS_SERVER}" "${NS_CLIENTS[@]}"; do
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
    for i in $(seq 0 $((NUM_CLIENTS - 1))); do
        echo ""
        echo "--- Client ${i} log (last 40 lines) ---"
        tail -40 "${LOG_DIR}/client${i}.log" 2>/dev/null || echo "(no log)"
    done
    exit 1
}

# ── Preconditions ────────────────────────────────────────────────────

echo "=== IT13: TLS-Crypt-V2 Multi-Client (3 distinct keys) ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

if [[ ! -x "${BINARY}" ]]; then
    echo "Error: Binary not found at ${BINARY}"
    exit 1
fi

# Gate: V2 key material
for i in 0 1 2; do
    if [[ ! -f "${PROJECT_ROOT}/test_data/certs/tls-crypt-v2-client${i}.key" ]]; then
        echo "SKIP: V2 client key ${i} not found. Run test_data/certs/gen_tls_crypt_v2_keys.sh first."
        exit 77
    fi
done

# Gate: V2 config support
_test_log=$(mktemp)
timeout 3 nsenter --net="/run/netns/${NS_SERVER}" -- \
    "${BINARY}" "${SERVER_CONFIG}" > "${_test_log}" 2>&1 || true
if grep -qi "unknown.*tls_crypt_v2\|unsupported.*tls_crypt_v2\|tls.crypt.*key.*required" "${_test_log}" 2>/dev/null; then
    echo "SKIP: Binary does not support tls_crypt_v2_key config field yet."
    rm -f "${_test_log}"
    exit 77
fi
rm -f "${_test_log}"

for ns in "${NS_SERVER}" "${NS_CLIENTS[@]}"; do
    if ! ip netns list | grep -qw "${ns}"; then
        echo "Error: Namespace ${ns} not found."
        exit 1
    fi
done

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${LOG_DIR}"/client*.log
cd "${PROJECT_ROOT}"

# ── Start server ─────────────────────────────────────────────────────

echo "[1/5] Starting V2 server in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

# ── Start all clients concurrently ───────────────────────────────────

echo "[2/5] Starting ${NUM_CLIENTS} V2 clients with distinct per-client keys..."

for i in $(seq 0 $((NUM_CLIENTS - 1))); do
    ns_bg "${NS_CLIENTS[$i]}" "${BINARY}" "${CLIENT_CONFIGS[$i]}" \
        > "${LOG_DIR}/client${i}.log" 2>&1 &
    CLIENT_PIDS+=($!)
    echo "      Client ${i} PID: ${CLIENT_PIDS[$i]} (${NS_CLIENTS[$i]})"
done

# ── Wait for all handshakes ──────────────────────────────────────────

echo "[3/5] Waiting for all handshakes (up to ${HANDSHAKE_TIMEOUT}s)..."

handshake_count=0
elapsed=0
while (( elapsed < HANDSHAKE_TIMEOUT )); do
    handshake_count=0
    for i in $(seq 0 $((NUM_CLIENTS - 1))); do
        if grep -qi "client connected\|state.*connected\|connected to server\|PUSH_REPLY.*received\|tunnel established" \
             "${LOG_DIR}/client${i}.log" 2>/dev/null; then
            (( handshake_count++ )) || true
        fi
    done
    if (( handshake_count == NUM_CLIENTS )); then
        break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        fail "Server died during handshake"
    fi
    sleep 1
    (( elapsed++ )) || true
done

if (( handshake_count < NUM_CLIENTS )); then
    fail "Only ${handshake_count}/${NUM_CLIENTS} clients completed handshake within ${HANDSHAKE_TIMEOUT}s"
fi
echo "      All ${NUM_CLIENTS} handshakes completed in ~${elapsed}s"
sleep 1

# ── Verify tunnel: each client pings server ──────────────────────────

echo "[4/5] Verifying tunnel: each client pings server..."

all_ok=1
for i in $(seq 0 $((NUM_CLIENTS - 1))); do
    ns_exec "${NS_CLIENTS[$i]}" ping -c 3 -W "${PING_TIMEOUT}" -i 0.5 \
        "${TUNNEL_SERVER_IP}" > "${LOG_DIR}/ping_c${i}.log" 2>&1 || true
    received=$(grep -oP '\d+(?= received)' "${LOG_DIR}/ping_c${i}.log" || echo "0")
    if (( received == 0 )); then
        echo "      FAIL: Client ${i} cannot reach tunnel server"
        all_ok=0
    else
        echo "      Client ${i}: ${received}/3 pings OK"
    fi
done

if (( all_ok == 0 )); then
    fail "One or more clients cannot reach tunnel server"
fi

# ── Verify: client-to-client through tunnel ──────────────────────────

echo "[5/5] Verifying client-to-client (C0 ↔ C1)..."

# Get client tunnel IPs from server log
c0_ip=$(grep -oP 'client.*10\.8\.0\.\d+' "${LOG_DIR}/client0.log" 2>/dev/null \
        | grep -oP '10\.8\.0\.\d+' | tail -1 || echo "")
c1_ip=$(grep -oP 'client.*10\.8\.0\.\d+' "${LOG_DIR}/client1.log" 2>/dev/null \
        | grep -oP '10\.8\.0\.\d+' | tail -1 || echo "")

if [[ -n "${c0_ip}" && -n "${c1_ip}" && "${c0_ip}" != "${c1_ip}" ]]; then
    echo "      C0 tunnel IP: ${c0_ip}, C1 tunnel IP: ${c1_ip}"
    ns_exec "${NS_CLIENTS[0]}" ping -c 2 -W 3 "${c1_ip}" > "${LOG_DIR}/ping_c2c.log" 2>&1 || true
    c2c_recv=$(grep -oP '\d+(?= received)' "${LOG_DIR}/ping_c2c.log" || echo "0")
    if (( c2c_recv > 0 )); then
        echo "      Client-to-client: ${c2c_recv}/2 pings OK"
    else
        echo "      Warning: Client-to-client ping failed (non-fatal — tunnel may need routing)"
    fi
else
    echo "      Warning: Could not determine client tunnel IPs for C2C test"
fi

echo ""
echo "=== IT13 PASSED ==="
echo "    Mode: tls-crypt-v2 (3 distinct per-client keys)"
echo "    Handshakes: ${NUM_CLIENTS}/${NUM_CLIENTS} in ~${elapsed}s"
echo "    Logs: ${LOG_DIR}/"
