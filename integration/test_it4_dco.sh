#!/bin/bash
# test_it4_dco.sh — IT4: DCO (kernel-offloaded) data path
#
# Validates end-to-end VPN with the ovpn-dco kernel module:
#   TLS handshake → key push to kernel → kernel encrypt/decrypt → tunnel ping
#
# This is the same logical flow as IT1 (single client handshake + ping) but
# with enable_dco=true, plus explicit verification that DCO devices were
# actually created (proving the kernel path was used, not a silent fallback
# to userspace).
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - ovpn-dco kernel module loaded or loadable
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#
# Usage: sudo ./test_it4_dco.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server_dco.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client_dco.json"

NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=20        # DCO may take slightly longer (kernel setup)
PING_COUNT=5
PING_TIMEOUT=3

LOG_DIR="/tmp/vpn-it4"
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
    # Clean up any lingering DCO devices in the namespaces
    for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
        for dev in $(ns_exec "$ns" ip -o link show 2>/dev/null \
                     | grep -o '[^ ]*ovpn[^ ]*' | head -10); do
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

echo "=== IT4: DCO Data Path (Kernel Offload) ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

# Gate: ovpn-dco kernel module must be available
if ! modprobe -n ovpn-dco 2>/dev/null && ! modprobe -n ovpn-dco-v2 2>/dev/null; then
    echo "SKIP: ovpn-dco kernel module not available"
    exit 77
fi
# Ensure the module is loaded
modprobe ovpn-dco 2>/dev/null || modprobe ovpn-dco-v2 2>/dev/null || {
    echo "SKIP: Failed to load ovpn-dco kernel module"
    exit 77
}
echo "      ovpn-dco module loaded"

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

# ── Start server ─────────────────────────────────────────────────────

echo "[1/7] Starting DCO server in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

# ── Start client ─────────────────────────────────────────────────────

echo "[2/7] Starting DCO client in ${NS_CLIENT}..."
ns_bg "${NS_CLIENT}" "${BINARY}" "${CLIENT_CONFIG}" \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!
echo "      Client PID: ${CLIENT_PID}"

# ── Wait for handshake ───────────────────────────────────────────────

echo "[3/7] Waiting up to ${HANDSHAKE_TIMEOUT}s for handshake..."

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

# ── Verify DCO devices exist ─────────────────────────────────────────

echo "[4/7] Verifying DCO devices..."

# Server: ovpn-dco0 in MP mode
if ns_exec "${NS_SERVER}" ip link show ovpn-dco0 &>/dev/null; then
    echo "      Server: ovpn-dco0 present"
else
    fail "Server DCO device ovpn-dco0 not found — kernel offload may not be active"
fi

# Client: ovpn-clientN (typically ovpn-client0)
client_dco_dev=""
for dev in $(ns_exec "${NS_CLIENT}" ip -o link show 2>/dev/null \
             | grep -oP 'ovpn-client\d+' | head -1); do
    client_dco_dev="$dev"
done

if [[ -n "${client_dco_dev}" ]]; then
    echo "      Client: ${client_dco_dev} present"
else
    fail "Client DCO device (ovpn-client*) not found — kernel offload may not be active"
fi

# Verify these are actually ovpn-dco devices (not TUN)
if ns_exec "${NS_SERVER}" ip -d link show ovpn-dco0 2>/dev/null | grep -q "ovpn-dco"; then
    echo "      Server device confirmed as ovpn-dco type"
else
    echo "      Warning: could not confirm ovpn-dco device type for server"
fi

if ns_exec "${NS_CLIENT}" ip -d link show "${client_dco_dev}" 2>/dev/null | grep -q "ovpn-dco"; then
    echo "      Client device confirmed as ovpn-dco type"
else
    echo "      Warning: could not confirm ovpn-dco device type for client"
fi

# Also verify DCO was logged (not userspace fallback)
if grep -qi "DCO\|kernel offload\|ovpn-dco" "${SERVER_LOG}" 2>/dev/null; then
    echo "      Server log confirms DCO mode"
else
    echo "      Warning: no DCO confirmation in server log"
fi

if grep -qi "DCO\|kernel offload\|ovpn-dco" "${CLIENT_LOG}" 2>/dev/null; then
    echo "      Client log confirms DCO mode"
else
    echo "      Warning: no DCO confirmation in client log"
fi

# ── Ping through tunnel ─────────────────────────────────────────────

echo "[5/7] Pinging tunnel gateway ${TUNNEL_SERVER_IP} from client..."
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

echo ""
echo "--- Ping Results ---"
cat "${LOG_DIR}/ping.log"

# ── Negative validation: tunnel requires VPN ─────────────────────────

echo ""
echo "[6/7] Negative validation — stopping VPN, confirming tunnel dies..."

kill -TERM "${CLIENT_PID}" 2>/dev/null || true
kill -TERM "${SERVER_PID}" 2>/dev/null || true
sleep 2
kill -9 "${CLIENT_PID}" 2>/dev/null || true
kill -9 "${SERVER_PID}" 2>/dev/null || true
wait 2>/dev/null || true
CLIENT_PID=""
SERVER_PID=""

# Remove DCO devices — they should auto-cleanup on process exit, but
# after kill -9 the kernel may not clean up immediately. Belt and suspenders.
for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
    for dev in $(ns_exec "$ns" ip -o link show 2>/dev/null \
                 | grep -oP 'ovpn-\S+' | sed 's/@.*//' | sort -u); do
        ns_exec "$ns" ip link del "$dev" 2>/dev/null || true
    done
    # Also clean any leftover TUN devices
    for dev in $(ns_exec "$ns" ip -o link show type tun 2>/dev/null \
                 | awk -F: '{print $2}' | tr -d ' '); do
        ns_exec "$ns" ip link del "$dev" 2>/dev/null || true
    done
done

if ns_exec "${NS_CLIENT}" ping -c 1 -W 2 "${TUNNEL_SERVER_IP}" &>/dev/null; then
    fail "Tunnel ping succeeded after VPN stopped — traffic may not be using the tunnel"
else
    echo "      Tunnel ping correctly failed after VPN stopped"
fi

# ── DCO device cleanup verification ─────────────────────────────────

echo ""
echo "[7/7] Verifying DCO devices cleaned up..."

stale_server=$(ns_exec "${NS_SERVER}" ip -o link show 2>/dev/null \
               | grep -c 'ovpn-' || true)
stale_client=$(ns_exec "${NS_CLIENT}" ip -o link show 2>/dev/null \
               | grep -c 'ovpn-' || true)

if (( stale_server == 0 && stale_client == 0 )); then
    echo "      All DCO devices cleaned up"
else
    echo "      Warning: ${stale_server} server + ${stale_client} client DCO device(s) remain"
fi

echo ""
echo "=== IT4 PASSED ==="
echo "    Logs: ${LOG_DIR}/"
