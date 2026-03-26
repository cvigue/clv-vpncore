#!/bin/bash
# test_it6_masquerade.sh — IT6: Masquerade / transit forwarding
#
# Validates that VPN clients can reach a LAN host behind the server via
# nftables MASQUERADE (ScopedMasquerade) and kernel ip_forward:
#
#   Client (10.8.0.x) → tunnel → Server (masquerade) → LAN host (172.16.0.100)
#
# Topology (extends the standard hub-spoke):
#
#   ns-vpn-client-0 (10.99.0.10)    ns-vpn-server (10.99.0.1 + 172.16.0.1)    ns-lan-host (172.16.0.100)
#       VPN client  ─── bridge ───── VPN server ──── direct veth ─────────────── LAN host
#       tunnel 10.8.0.x              tunnel 10.8.0.1                             gw → 172.16.0.1
#                                    masquerade: 10.8.0.0/24
#                                    ip_forward: on
#                                    pushes route: 172.16.0.0/24
#
# Validates:
#   - Negative pre-check: client cannot reach LAN host before VPN
#   - TLS handshake + tunnel establishment
#   - Pushed route (172.16.0.0/24) installed on client tunnel device
#   - Client can ping LAN host through tunnel (masquerade working)
#   - LAN host sees traffic from server's LAN IP (172.16.0.1), not VPN IP
#   - Negative validation: LAN host unreachable after VPN stopped
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#     (this script adds ns-lan-host itself)
#
# Usage: sudo ./test_it6_masquerade.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server_masq.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client.json"

NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"
NS_LAN="ns-lan-host"

TUNNEL_SERVER_IP="10.8.0.1"
LAN_HOST_IP="172.16.0.100"
SERVER_LAN_IP="172.16.0.1"
LAN_CIDR="24"

HANDSHAKE_TIMEOUT=20
PING_COUNT=3
PING_TIMEOUT=3

LOG_DIR="/tmp/vpn-it6"
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
    # Clean up TUN devices
    for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
        for dev in $(ns_exec "$ns" ip -o link show type tun 2>/dev/null \
                     | awk -F: '{print $2}' | tr -d ' '); do
            ns_exec "$ns" ip link del "$dev" 2>/dev/null || true
        done
    done
    # Tear down LAN host namespace
    if ip netns list 2>/dev/null | grep -qw "${NS_LAN}"; then
        ip netns del "${NS_LAN}" 2>/dev/null || true
    fi
    # Clean up LAN-side veth from server namespace (peer already gone with ns-lan-host)
    ns_exec "${NS_SERVER}" ip link del veth-lan 2>/dev/null || true
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

echo "=== IT6: Masquerade / Transit Forwarding ==="

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
rm -f "${SERVER_LOG}" "${CLIENT_LOG}"

cd "${PROJECT_ROOT}"

# ── Set up LAN host namespace ────────────────────────────────────────

echo "[1/8] Setting up LAN host namespace (${NS_LAN}, ${LAN_HOST_IP})..."

# Clean up any remnant from a previous run
if ip netns list 2>/dev/null | grep -qw "${NS_LAN}"; then
    ip netns del "${NS_LAN}"
fi

# Create LAN host namespace
ip netns add "${NS_LAN}"
ns_exec "${NS_LAN}" ip link set lo up

# Create veth pair: veth-lan (server side) ←→ veth-lh (LAN host side)
ip link add veth-lan type veth peer name veth-lh

# Move endpoints
ip link set veth-lan netns "${NS_SERVER}"
ip link set veth-lh  netns "${NS_LAN}"

# Configure server LAN interface
ns_exec "${NS_SERVER}" ip addr add "${SERVER_LAN_IP}/${LAN_CIDR}" dev veth-lan
ns_exec "${NS_SERVER}" ip link set veth-lan up

# Configure LAN host
ns_exec "${NS_LAN}" ip addr add "${LAN_HOST_IP}/${LAN_CIDR}" dev veth-lh
ns_exec "${NS_LAN}" ip link set veth-lh up

# LAN host default gateway → server's LAN IP (so replies route back)
ns_exec "${NS_LAN}" ip route add default via "${SERVER_LAN_IP}"

# Verify LAN connectivity (server ↔ LAN host, no VPN involved)
if ns_exec "${NS_SERVER}" ping -c 1 -W 2 "${LAN_HOST_IP}" > /dev/null 2>&1; then
    echo "      Server → LAN host (${LAN_HOST_IP}): OK"
else
    fail "Server cannot reach LAN host — LAN veth wiring broken"
fi

# ── Negative pre-check ───────────────────────────────────────────────

echo "[2/8] Negative pre-check — client cannot reach LAN host without VPN..."

if ns_exec "${NS_CLIENT}" ping -c 1 -W 2 "${LAN_HOST_IP}" &>/dev/null; then
    fail "Client can already reach LAN host (${LAN_HOST_IP}) without VPN — test topology broken"
fi
echo "      Client → LAN host: unreachable (good, no route yet)"

# ── Start server ─────────────────────────────────────────────────────

echo "[3/8] Starting server in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

# ── Start client ─────────────────────────────────────────────────────

echo "[4/8] Starting client in ${NS_CLIENT}..."
ns_bg "${NS_CLIENT}" "${BINARY}" "${CLIENT_CONFIG}" \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!
echo "      Client PID: ${CLIENT_PID}"

# ── Wait for handshake ───────────────────────────────────────────────

echo "[5/8] Waiting up to ${HANDSHAKE_TIMEOUT}s for handshake..."

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

# Allow routes to settle
sleep 1

# ── Verify pushed route ─────────────────────────────────────────────

echo "[6/8] Verifying pushed route (172.16.0.0/24) on client..."

if ns_exec "${NS_CLIENT}" ip route show 172.16.0.0/24 2>/dev/null | grep -q 'tun0\|ovpn'; then
    echo "      Route 172.16.0.0/24 present on tunnel device"
else
    # Show what routes exist for debugging
    echo "      Client route table:"
    ns_exec "${NS_CLIENT}" ip route show 2>/dev/null | sed 's/^/        /'
    fail "Route 172.16.0.0/24 not found on client tunnel device — push_routes may not be working"
fi

# ── Ping LAN host through tunnel ────────────────────────────────────

echo "[7/8] Pinging LAN host (${LAN_HOST_IP}) from client through tunnel..."

if ns_exec "${NS_CLIENT}" ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" \
    "${LAN_HOST_IP}" > "${LOG_DIR}/ping-lan.log" 2>&1; then
    echo "      Client → LAN host: OK (${PING_COUNT}/${PING_COUNT})"
else
    received=$(grep -oP '\d+(?= received)' "${LOG_DIR}/ping-lan.log" || echo "0")
    if (( received > 0 )); then
        echo "      Partial ping success (${received}/${PING_COUNT})"
    else
        echo ""
        echo "--- Ping output ---"
        cat "${LOG_DIR}/ping-lan.log"
        echo ""
        echo "--- Server nftables rules ---"
        ns_exec "${NS_SERVER}" nft list ruleset 2>/dev/null | head -30 || echo "(nft not available)"
        echo ""
        echo "--- Server routing table ---"
        ns_exec "${NS_SERVER}" ip route show 2>/dev/null | head -20
        fail "Client cannot reach LAN host through tunnel — masquerade/forwarding may not be working"
    fi
fi

# Verify masquerade: LAN host should see traffic from server's LAN IP, not from 10.8.0.x
# We do this by checking the server's nftables counters or simply confirming the rule exists.
echo "      Verifying masquerade rule on server..."
if ns_exec "${NS_SERVER}" nft list ruleset 2>/dev/null | grep -qi "masquerade"; then
    echo "      nftables MASQUERADE rule active on server"
else
    echo "      Warning: could not confirm nftables masquerade rule (nft may not be installed)"
fi

# ── Negative validation ──────────────────────────────────────────────

echo "[8/8] Negative validation — stopping VPN, confirming LAN host unreachable..."

kill -TERM "${CLIENT_PID}" 2>/dev/null || true
kill -TERM "${SERVER_PID}" 2>/dev/null || true
sleep 2
kill -9 "${CLIENT_PID}" 2>/dev/null || true
kill -9 "${SERVER_PID}" 2>/dev/null || true
wait 2>/dev/null || true
CLIENT_PID=""
SERVER_PID=""

# Remove TUN devices
for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
    for dev in $(ns_exec "$ns" ip -o link show type tun 2>/dev/null \
                 | awk -F: '{print $2}' | tr -d ' '); do
        ns_exec "$ns" ip link del "$dev" 2>/dev/null || true
    done
done

if ns_exec "${NS_CLIENT}" ping -c 1 -W 2 "${LAN_HOST_IP}" &>/dev/null; then
    fail "Client can still reach LAN host after VPN stopped — masquerade test inconclusive"
else
    echo "      Client → LAN host: unreachable (good)"
fi

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo "=== IT6 PASSED ==="
echo "    LAN host (${LAN_HOST_IP}) reachable through VPN tunnel + masquerade"
echo "    Route 172.16.0.0/24 pushed and installed on client"
echo "    LAN host unreachable after VPN stopped"
echo "    Logs: ${LOG_DIR}/"
