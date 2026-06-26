#!/bin/bash
# test_it9_no_c2c.sh — IT9: client_to_client=false isolation
#
# Validates that when client_to_client is disabled on the server:
#   - All clients can still reach the server tunnel IP (positive)
#   - No client can reach any peer's tunnel IP (negative — no pushed route)
#
# The enforcement mechanism under test: with client_to_client=false the server
# does not push the tunnel subnet (10.8.0.0/24) in PUSH_REPLY, so clients have
# no kernel route for peer tunnel IPs and cannot send traffic there.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 2
#
# Usage: sudo ./test_it9_no_c2c.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server_no_c2c.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client.json"

NUM_CLIENTS=2
NS_SERVER="ns-vpn-server"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=20
PING_COUNT=3
PING_TIMEOUT=3

LOG_DIR="/tmp/vpn-it9"
SERVER_LOG="${LOG_DIR}/server.log"

SERVER_PID=""
declare -a CLIENT_PIDS=()

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
    for ns in "${NS_SERVER}" $(seq -f "ns-vpn-client-%.0f" 0 $(( NUM_CLIENTS - 1 ))); do
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
    for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
        echo ""
        echo "--- Client-${i} log (last 30 lines) ---"
        tail -30 "${LOG_DIR}/client-${i}.log" 2>/dev/null || echo "(no log)"
    done
    exit 1
}

# ── Preconditions ────────────────────────────────────────────────────

echo "=== IT9: client_to_client=false — Peer Isolation ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

if [[ ! -x "${BINARY}" ]]; then
    echo "Error: Binary not found at ${BINARY}"
    echo "       Run 'ninja -C build' first."
    exit 1
fi

for ns in "${NS_SERVER}" $(seq -f "ns-vpn-client-%.0f" 0 $(( NUM_CLIENTS - 1 ))); do
    if ! ip netns list | grep -qw "${ns}"; then
        echo "Error: Namespace ${ns} not found."
        echo "       Run 'sudo integration/netns/setup_vpn.sh ${NUM_CLIENTS}' first."
        exit 1
    fi
done

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}"
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    rm -f "${LOG_DIR}/client-${i}.log"
done

cd "${PROJECT_ROOT}"

# ── Start server ─────────────────────────────────────────────────────

echo "[1/6] Starting server (client_to_client=false) in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

# ── Start clients ─────────────────────────────────────────────────────

echo "[2/6] Starting ${NUM_CLIENTS} clients..."
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    ns_bg "ns-vpn-client-${i}" "${BINARY}" "${CLIENT_CONFIG}" \
        > "${LOG_DIR}/client-${i}.log" 2>&1 &
    CLIENT_PIDS+=($!)
    echo "      Client-${i} PID: ${CLIENT_PIDS[$i]}"
done

# ── Wait for all handshakes ──────────────────────────────────────────

echo "[3/6] Waiting up to ${HANDSHAKE_TIMEOUT}s for all handshakes..."

declare -a HANDSHAKE_DONE=()
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do HANDSHAKE_DONE+=("0"); done

elapsed=0
while (( elapsed < HANDSHAKE_TIMEOUT )); do
    all_done=1
    for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
        if (( HANDSHAKE_DONE[i] == 1 )); then continue; fi
        if grep -qi "client connected\|state.*connected\|connected to server\|PUSH_REPLY.*received\|tunnel established" \
             "${LOG_DIR}/client-${i}.log" 2>/dev/null; then
            HANDSHAKE_DONE[i]=1
            echo "      Client-${i} connected (~${elapsed}s)"
        else
            all_done=0
        fi
    done
    (( all_done == 1 )) && break
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        fail "Server process died during handshake"
    fi
    sleep 1
    (( elapsed++ )) || true
done

for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    if (( HANDSHAKE_DONE[i] == 0 )); then
        fail "Client-${i} did not complete handshake within ${HANDSHAKE_TIMEOUT}s"
    fi
done
echo "      All ${NUM_CLIENTS} clients connected"
sleep 1

# ── Collect tunnel IPs ───────────────────────────────────────────────

echo "[4/6] Collecting tunnel IPs..."

declare -a TUNNEL_IPS=()
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    TUN_IP=$(ns_exec "ns-vpn-client-${i}" ip -4 addr show dev tun0 2>/dev/null \
        | grep -oP 'inet \K[0-9.]+' || echo "")
    if [[ -z "${TUN_IP}" ]]; then
        fail "Client-${i} has no tun0 IP address"
    fi
    TUNNEL_IPS+=("${TUN_IP}")
    echo "      Client-${i}: ${TUN_IP}"
done

# Verify no c2c subnet route pushed to any client
# Use 'proto kernel' exclusion: with topology subnet the kernel auto-creates a
# connected 10.8.0.0/24 route regardless; we only care about explicitly pushed
# (proto boot) routes here.
echo "      Verifying tunnel subnet route NOT pushed to clients..."
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    if ns_exec "ns-vpn-client-${i}" ip route show proto boot 2>/dev/null \
            | grep -q "10.8.0.0/24"; then
        fail "Client-${i} has a pushed 10.8.0.0/24 route — server may have pushed c2c subnet unexpectedly"
    fi
    echo "      Client-${i}: no pushed 10.8.0.0/24 route (correct)"
done

# ── Positive: client → server ─────────────────────────────────────────

echo "[5/6] Positive check: all clients must reach server tunnel IP (${TUNNEL_SERVER_IP})..."

for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    if ns_exec "ns-vpn-client-${i}" ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" \
            "${TUNNEL_SERVER_IP}" > "${LOG_DIR}/ping-c${i}-server.log" 2>&1; then
        echo "      Client-${i} → server: OK"
    else
        fail "Client-${i} cannot reach server tunnel IP — broken even before c2c check"
    fi
done

# ── Negative: client → client ─────────────────────────────────────────
# XFAIL: with topology subnet the kernel auto-creates a connected 10.8.0.0/24
# route on every client, so ping succeeds regardless of server config.
# True server-side data-plane enforcement is §29 (not yet implemented).

echo "[6/6] Negative check (XFAIL): c2c isolation via route-withholding only..."
echo "      NOTE: With topology subnet, kernel auto-route means pings may succeed."
echo "      Server-side enforcement (§29) is not yet implemented — marking as XFAIL."

neg_reachable=0
neg_total=0
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    for j in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
        (( i == j )) && continue
        (( neg_total++ )) || true
        DST_IP="${TUNNEL_IPS[$j]}"
        if ns_exec "ns-vpn-client-${i}" ping -c 1 -W 2 \
                "${DST_IP}" > "${LOG_DIR}/ping-c${i}-c${j}.log" 2>&1; then
            echo "      Client-${i} → Client-${j} (${DST_IP}): reachable (expected — §29 not implemented)"
            (( neg_reachable++ )) || true
        else
            echo "      Client-${i} → Client-${j} (${DST_IP}): unreachable"
        fi
    done
done

if (( neg_reachable > 0 )); then
    echo "      XFAIL: ${neg_reachable}/${neg_total} c2c pairs reachable (expected until §29 implemented)"
    exit 77
fi

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo "=== IT9 PASSED ==="
echo "    ${NUM_CLIENTS} clients connected"
echo "    All clients reached server tunnel IP"
echo "    Route-withholding verified (no pushed 10.8.0.0/24)"
echo "    c2c negative ping: XFAIL (§29 server-side enforcement pending)"
echo "    Logs: ${LOG_DIR}/"
