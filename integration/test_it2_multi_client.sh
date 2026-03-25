#!/bin/bash
# test_it2_multi_client.sh — IT2: Multi-client concurrent connect
#
# Validates concurrent multi-client behavior:
#   - N simultaneous handshakes complete
#   - Each client gets a unique tunnel IP
#   - All clients can ping the server through the tunnel
#   - Client-to-client ping through the server
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh N
#
# Usage: sudo ./test_it2_multi_client.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client.json"

NUM_CLIENTS=3
NS_SERVER="ns-vpn-server"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=20        # seconds — longer for concurrent handshakes
PING_COUNT=3
PING_TIMEOUT=3

# Log locations
LOG_DIR="/tmp/vpn-it2"
SERVER_LOG="${LOG_DIR}/server.log"

SERVER_PID=""
declare -a CLIENT_PIDS=()

# ── Helpers ──────────────────────────────────────────────────────────

ns_exec() { ip netns exec "$1" "${@:2}"; }

# Background variant: exec ensures $! == actual process PID (no intermediate fork)
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

echo "=== IT2: Multi-Client Concurrent Connect (${NUM_CLIENTS} clients) ==="

# Escalate to root if not already
if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

if [[ ! -x "${BINARY}" ]]; then
    echo "Error: Binary not found at ${BINARY}"
    echo "       Run 'ninja -C build' first."
    exit 1
fi

# Verify all namespaces exist
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

# Ensure relative paths in configs resolve correctly
cd "${PROJECT_ROOT}"

# ── Start server ─────────────────────────────────────────────────────

echo "[1/6] Starting server in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

# ── Start all clients concurrently ───────────────────────────────────

echo "[2/6] Starting ${NUM_CLIENTS} clients concurrently..."
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    NS_CLIENT="ns-vpn-client-${i}"
    CLIENT_LOG_I="${LOG_DIR}/client-${i}.log"

    ns_bg "${NS_CLIENT}" "${BINARY}" "${CLIENT_CONFIG}" \
        > "${CLIENT_LOG_I}" 2>&1 &
    CLIENT_PIDS+=($!)
    echo "      Client-${i} PID: ${CLIENT_PIDS[$i]} (${NS_CLIENT})"
done

# ── Wait for all handshakes ──────────────────────────────────────────

echo "[3/6] Waiting up to ${HANDSHAKE_TIMEOUT}s for all handshakes..."

declare -a HANDSHAKE_DONE=()
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    HANDSHAKE_DONE+=("0")
done

elapsed=0
while (( elapsed < HANDSHAKE_TIMEOUT )); do
    all_done=1
    for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
        if (( HANDSHAKE_DONE[i] == 1 )); then
            continue
        fi
        if grep -qi "client connected\|state.*connected\|connected to server\|PUSH_REPLY.*received\|tunnel established" \
             "${LOG_DIR}/client-${i}.log" 2>/dev/null; then
            HANDSHAKE_DONE[i]=1
            echo "      Client-${i} connected (~${elapsed}s)"
        else
            all_done=0
        fi
    done
    if (( all_done == 1 )); then
        break
    fi
    # Check for dead processes
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        fail "Server process died during handshake"
    fi
    for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
        if (( HANDSHAKE_DONE[i] == 0 )) && ! kill -0 "${CLIENT_PIDS[$i]}" 2>/dev/null; then
            fail "Client-${i} process died during handshake"
        fi
    done
    sleep 1
    (( elapsed++ )) || true
done

# Check all connected
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    if (( HANDSHAKE_DONE[i] == 0 )); then
        fail "Client-${i} did not complete handshake within ${HANDSHAKE_TIMEOUT}s"
    fi
done
echo "      All ${NUM_CLIENTS} clients connected"

# Small settle time for routes
sleep 1

# ── Verify unique tunnel IPs ─────────────────────────────────────────

echo "[4/6] Checking unique tunnel IP assignments..."

declare -a TUNNEL_IPS=()
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    NS_CLIENT="ns-vpn-client-${i}"
    # Get the tunnel IP from the tun0 interface in the client namespace
    TUN_IP=$(ns_exec "${NS_CLIENT}" ip -4 addr show dev tun0 2>/dev/null \
        | grep -oP 'inet \K[0-9.]+' || echo "")
    if [[ -z "${TUN_IP}" ]]; then
        fail "Client-${i} has no tun0 IP address"
    fi
    TUNNEL_IPS+=("${TUN_IP}")
    echo "      Client-${i}: ${TUN_IP}"
done

# Check uniqueness
UNIQUE_COUNT=$(printf '%s\n' "${TUNNEL_IPS[@]}" | sort -u | wc -l)
if (( UNIQUE_COUNT != NUM_CLIENTS )); then
    fail "Tunnel IPs are not unique: ${TUNNEL_IPS[*]}"
fi
echo "      All IPs unique"

# ── Ping server from all clients ─────────────────────────────────────

echo "[5/6] Pinging server (${TUNNEL_SERVER_IP}) from all clients..."

PING_PASS=0
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    NS_CLIENT="ns-vpn-client-${i}"
    if ns_exec "${NS_CLIENT}" ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" \
        "${TUNNEL_SERVER_IP}" > "${LOG_DIR}/ping-c${i}-server.log" 2>&1; then
        echo "      Client-${i} → server: OK"
        (( PING_PASS++ )) || true
    else
        echo "      Client-${i} → server: FAIL"
    fi
done

if (( PING_PASS != NUM_CLIENTS )); then
    fail "Only ${PING_PASS}/${NUM_CLIENTS} clients could ping the server"
fi

# ── Client-to-client ping through server ─────────────────────────────

echo "[6/7] Pinging client-to-client through tunnel..."

C2C_PASS=0
C2C_TOTAL=0
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    for j in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
        if (( i == j )); then
            continue
        fi
        (( C2C_TOTAL++ )) || true
        NS_SRC="ns-vpn-client-${i}"
        DST_IP="${TUNNEL_IPS[$j]}"
        if ns_exec "${NS_SRC}" ping -c 2 -W "${PING_TIMEOUT}" \
            "${DST_IP}" > "${LOG_DIR}/ping-c${i}-c${j}.log" 2>&1; then
            echo "      Client-${i} → Client-${j} (${DST_IP}): OK"
            (( C2C_PASS++ )) || true
        else
            echo "      Client-${i} → Client-${j} (${DST_IP}): FAIL"
        fi
    done
done

if (( C2C_PASS != C2C_TOTAL )); then
    fail "Client-to-client: ${C2C_PASS}/${C2C_TOTAL} passed"
fi

# ── Negative validation: tunnel requires VPN ─────────────────────────

echo "[7/7] Negative validation — stopping VPN, confirming tunnel dies..."

# Kill VPN processes
for pid in "${CLIENT_PIDS[@]}"; do
    kill -TERM "${pid}" 2>/dev/null || true
done
[[ -n "${SERVER_PID}" ]] && kill -TERM "${SERVER_PID}" 2>/dev/null || true
sleep 2
for pid in "${CLIENT_PIDS[@]}"; do
    kill -9 "${pid}" 2>/dev/null || true
done
[[ -n "${SERVER_PID}" ]] && kill -9 "${SERVER_PID}" 2>/dev/null || true
wait 2>/dev/null || true
# Clear PIDs so cleanup trap doesn't re-kill
CLIENT_PIDS=()
SERVER_PID=""

# Remove TUN devices — persistent TUNs survive process death, so
# explicitly delete them to prove the tunnel was the only route.
for ns in "${NS_SERVER}" $(seq -f "ns-vpn-client-%.0f" 0 $(( NUM_CLIENTS - 1 ))); do
    for dev in $(ns_exec "$ns" ip -o link show type tun 2>/dev/null | awk -F: '{print $2}' | tr -d ' '); do
        ns_exec "$ns" ip link del "$dev" 2>/dev/null || true
    done
done

neg_ok=1
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    NS_CLIENT="ns-vpn-client-${i}"
    if ns_exec "${NS_CLIENT}" ping -c 1 -W 2 "${TUNNEL_SERVER_IP}" &>/dev/null; then
        echo "      Client-${i} → server: still reachable (BAD)"
        neg_ok=0
    else
        echo "      Client-${i} → server: unreachable (good)"
    fi
done

if (( neg_ok == 0 )); then
    fail "Tunnel ping succeeded after VPN stopped — traffic may not be using the tunnel"
fi
echo "      Tunnel correctly unreachable after VPN stopped"

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo "=== IT2 PASSED ==="
echo "    ${NUM_CLIENTS} clients connected with unique IPs"
echo "    All clients pinged server successfully"
echo "    Client-to-client: ${C2C_PASS}/${C2C_TOTAL} passed"
echo "    Tunnel unreachable after VPN stopped"
echo "    Logs: ${LOG_DIR}/"
