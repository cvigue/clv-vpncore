#!/bin/bash
# test_it11_c2c_full_bypass.sh — IT11: client_to_client=false full-route bypass attempt
#
# Tests that the server blocks client-to-client forwarding at the data path
# when BOTH clients have a complete, symmetric routing setup — i.e., the exact
# situation that would exist if an attacker or misconfigured host manually
# replicated what the server would have pushed with client_to_client=true.
#
# IT10 only injects a route on the sending client, so the return path is absent
# and the ping silently fails regardless of server behaviour.  IT11 removes that
# ambiguity by injecting the subnet route on both sides first, making the return
# path available.  Only genuine server-side enforcement can cause the ping to fail.
#
# Scenario:
#   - Server: client_to_client=false
#   - Two clients connect and receive no tunnel subnet route
#   - 10.8.0.0/24 via tun0 is manually injected into BOTH client namespaces
#   - client-0 attempts to ping client-1's tunnel IP
#
# Expected result:
#   The ping MUST fail.  The server must drop or not forward the packet at the
#   data path regardless of client-side routing state.
#
# If this test fails (ping SUCCEEDS):
#   The enforcement gap is confirmed: client_to_client=false is purely a
#   "don't push the route" hint.  Server-side enforcement is needed in
#   UserspaceDataChannel::StartTunReceiver (and EncryptTunPacket) to drop
#   packets whose source and destination both belong to the tunnel pool.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 2
#
# Usage: sudo ./test_it11_c2c_full_bypass.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server_no_c2c.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client.json"

NUM_CLIENTS=2
NS_SERVER="ns-vpn-server"

TUNNEL_SERVER_IP="10.8.0.1"
TUNNEL_SUBNET="10.8.0.0/24"
HANDSHAKE_TIMEOUT=20
PING_TIMEOUT=3

LOG_DIR="/tmp/vpn-it11"
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

echo "=== IT11: client_to_client=false — Full Symmetric Route Bypass Attempt ==="
echo "    (both clients self-add routes; only server-side enforcement can block)"

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
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do rm -f "${LOG_DIR}/client-${i}.log"; done

cd "${PROJECT_ROOT}"

# ── Start server ─────────────────────────────────────────────────────

echo "[1/7] Starting server (client_to_client=false) in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

# ── Start clients ─────────────────────────────────────────────────────

echo "[2/7] Starting ${NUM_CLIENTS} clients..."
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    ns_bg "ns-vpn-client-${i}" "${BINARY}" "${CLIENT_CONFIG}" \
        > "${LOG_DIR}/client-${i}.log" 2>&1 &
    CLIENT_PIDS+=($!)
    echo "      Client-${i} PID: ${CLIENT_PIDS[$i]}"
done

# ── Wait for all handshakes ──────────────────────────────────────────

echo "[3/7] Waiting up to ${HANDSHAKE_TIMEOUT}s for all handshakes..."

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
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then fail "Server process died"; fi
    sleep 1
    (( elapsed++ )) || true
done

for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    (( HANDSHAKE_DONE[i] == 0 )) && fail "Client-${i} handshake timed out"
done
echo "      All ${NUM_CLIENTS} clients connected"
sleep 1

# ── Collect tunnel IPs ───────────────────────────────────────────────

echo "[4/7] Collecting tunnel IPs..."

declare -a TUNNEL_IPS=()
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    TUN_IP=$(ns_exec "ns-vpn-client-${i}" ip -4 addr show dev tun0 2>/dev/null \
        | grep -oP 'inet \K[0-9.]+' || echo "")
    [[ -z "${TUN_IP}" ]] && fail "Client-${i} has no tun0 IP"
    TUNNEL_IPS+=("${TUN_IP}")
    echo "      Client-${i}: ${TUN_IP}"
done

# Confirm no c2c subnet route was pushed
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    if ns_exec "ns-vpn-client-${i}" ip route show 2>/dev/null | grep -q "${TUNNEL_SUBNET}"; then
        fail "Client-${i} already has ${TUNNEL_SUBNET} route — server pushed c2c route unexpectedly"
    fi
done
echo "      Confirmed: no ${TUNNEL_SUBNET} route on any client (server withheld correctly)"

# ── Positive: client → server still works ────────────────────────────

echo "[5/7] Positive check: clients must still reach server (${TUNNEL_SERVER_IP})..."
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    if ! ns_exec "ns-vpn-client-${i}" ping -c 2 -W "${PING_TIMEOUT}" \
            "${TUNNEL_SERVER_IP}" > "${LOG_DIR}/ping-c${i}-server.log" 2>&1; then
        fail "Client-${i} cannot reach server tunnel IP — environment broken"
    fi
    echo "      Client-${i} → server: OK"
done

# ── Inject tunnel subnet route on BOTH clients ────────────────────────

echo "[6/7] Injecting ${TUNNEL_SUBNET} route into both client namespaces..."
echo "      (simulating a full symmetric self-configuration matching client_to_client=true)"

for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    ns_exec "ns-vpn-client-${i}" ip route add "${TUNNEL_SUBNET}" dev tun0
    if ! ns_exec "ns-vpn-client-${i}" ip route show | grep -q "${TUNNEL_SUBNET}"; then
        fail "Route injection failed on client-${i} — check permissions"
    fi
    echo "      Client-${i}: $(ns_exec "ns-vpn-client-${i}" ip route show | grep "${TUNNEL_SUBNET}")"
done

# Brief settle — let any buffered packets drain
sleep 1

# ── Negative: server must block forwarding despite symmetric routes ───

echo "[7/7] Negative check: client-0 must NOT reach client-1 (${TUNNEL_IPS[1]}) despite symmetric routes..."
echo "      Return path is now available — only server-side enforcement can block this."

if ns_exec "ns-vpn-client-0" ping -c 3 -W "${PING_TIMEOUT}" \
        "${TUNNEL_IPS[1]}" > "${LOG_DIR}/ping-bypass.log" 2>&1; then
    echo ""
    echo "  !! ENFORCEMENT GAP CONFIRMED !!"
    echo "  client-0 reached client-1 (${TUNNEL_IPS[1]}) with symmetric routes in place."
    echo "  client_to_client=false provides no data-path enforcement."
    echo "  The server's StartTunReceiver forwards any TUN packet matching a session"
    echo "  routing table entry, with no check against the client_to_client flag."
    echo "  Server-side enforcement is required in StartTunReceiver/EncryptTunPacket."
    fail "c2c bypass succeeded — server does not enforce isolation at the data path"
else
    echo "      Client-0 → Client-1 (${TUNNEL_IPS[1]}): blocked (correct)"
fi

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo "=== IT11 PASSED ==="
echo "    Server blocked c2c forwarding at the data path"
echo "    client_to_client=false enforced even with symmetric client-side routes"
echo "    Logs: ${LOG_DIR}/"
