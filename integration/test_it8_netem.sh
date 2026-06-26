#!/bin/bash
# test_it8_netem.sh — IT8: Graceful behavior under latency + loss
#
# Smoke test: applies 100 ms delay + 1% packet loss via tc netem on the
# underlay veth interfaces, then verifies the VPN handshake completes and
# the tunnel carries traffic despite the degraded network.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#   - tc (iproute2) with netem support
#
# Usage: sudo ./test_it8_netem.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client.json"

NS_BRIDGE="ns-vpn-bridge"
NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=30        # generous — retransmits may be needed
PING_COUNT=20
PING_TIMEOUT=5              # per-ping, accounts for 100ms added RTT
PING_MIN_SUCCESS=16         # ≥80% of 20

NETEM_DELAY="100ms"
NETEM_LOSS="1%"

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
    # Remove netem qdiscs (best-effort — interfaces may already be gone)
    ns_exec "${NS_BRIDGE}" tc qdisc del dev veth-br-srv root 2>/dev/null || true
    ns_exec "${NS_BRIDGE}" tc qdisc del dev veth-br-c0  root 2>/dev/null || true
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

echo "=== IT8: Netem — Latency + Loss Smoke Test ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

# Gate: netem module must be available
if ! tc qdisc add dev lo root netem delay 0ms 2>/dev/null; then
    echo "SKIP: tc netem not available on this system"
    tc qdisc del dev lo root 2>/dev/null || true
    exit 77
fi
tc qdisc del dev lo root 2>/dev/null || true

if [[ ! -x "${BINARY}" ]]; then
    echo "Error: Binary not found at ${BINARY}"
    exit 1
fi

for ns in "${NS_SERVER}" "${NS_CLIENT}" "${NS_BRIDGE}"; do
    if ! ip netns list | grep -qw "${ns}"; then
        echo "Error: Namespace ${ns} not found."
        exit 1
    fi
done

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}"
cd "${PROJECT_ROOT}"

# ── Apply netem ──────────────────────────────────────────────────────

echo "[1/6] Applying netem (${NETEM_DELAY} delay, ${NETEM_LOSS} loss) on bridge veths..."

ns_exec "${NS_BRIDGE}" tc qdisc add dev veth-br-srv root netem delay ${NETEM_DELAY} loss ${NETEM_LOSS}
ns_exec "${NS_BRIDGE}" tc qdisc add dev veth-br-c0  root netem delay ${NETEM_DELAY} loss ${NETEM_LOSS}

# Quick sanity: underlay ping should show ~200ms RTT (100ms each direction)
echo "      Verifying underlay degradation..."
rtt=$(ns_exec "${NS_CLIENT}" ping -c 3 -W 3 10.99.0.1 2>/dev/null \
      | grep -oP 'rtt.*= \K[\d.]+' | head -1 || echo "0")
if [[ -n "${rtt}" ]] && (( $(echo "${rtt} > 50" | bc -l 2>/dev/null || echo 0) )); then
    echo "      Underlay RTT: ~${rtt}ms (netem active)"
else
    echo "      Warning: underlay RTT ${rtt}ms — netem may not be effective"
fi

# ── Start server + client ────────────────────────────────────────────

echo "[2/6] Starting server in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

echo "[3/6] Starting client, waiting for handshake (up to ${HANDSHAKE_TIMEOUT}s)..."
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
    fail "Handshake did not complete within ${HANDSHAKE_TIMEOUT}s (under netem)"
fi
echo "      Handshake completed in ~${elapsed}s"
sleep 1

# ── Verify tunnel under degradation ─────────────────────────────────

echo "[4/6] Pinging tunnel (${PING_COUNT} packets, expect ≥${PING_MIN_SUCCESS} success)..."

ns_exec "${NS_CLIENT}" ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" -i 0.5 \
    "${TUNNEL_SERVER_IP}" > "${LOG_DIR}/ping.log" 2>&1 || true

received=$(grep -oP '\d+(?= received)' "${LOG_DIR}/ping.log" || echo "0")
echo "      Received: ${received}/${PING_COUNT}"

if (( received >= PING_MIN_SUCCESS )); then
    echo "      Tunnel functional under netem (${received}/${PING_COUNT} ≥ ${PING_MIN_SUCCESS})"
else
    echo ""
    cat "${LOG_DIR}/ping.log"
    fail "Too many tunnel pings lost: ${received}/${PING_COUNT} (need ≥${PING_MIN_SUCCESS})"
fi

# ── Check for retransmits (informational) ────────────────────────────

echo "[5/6] Checking control-channel retransmits (informational)..."
retransmit_count=$(grep -ci "retransmit" "${CLIENT_LOG}" 2>/dev/null || true)
retransmit_count="${retransmit_count:-0}"
echo "      Client retransmits logged: ${retransmit_count}"

# ── Negative validation ──────────────────────────────────────────────

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
echo "    Netem: ${NETEM_DELAY} delay, ${NETEM_LOSS} loss"
echo "    Handshake: ~${elapsed}s, Tunnel: ${received}/${PING_COUNT} pings"
echo "    Retransmits: ${retransmit_count}"
echo "    Logs: ${LOG_DIR}/"
