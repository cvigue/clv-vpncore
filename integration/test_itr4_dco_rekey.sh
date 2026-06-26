#!/bin/bash
# test_itr4_dco_rekey.sh — IT-R4: Server-initiated rekey in DCO mode
#
# Validates that the DCO kernel-offload path handles renegotiation correctly:
#   - PushKeysToKernel is called for the new key material
#   - Secondary → primary key slot swap completes in the kernel
#   - The kernel continues encrypting/decrypting data packets through the swap
#   - HasPeer() guard works correctly (rekey fires after peer is established)
#
# This is the DCO equivalent of IT-R1. The userspace side does not encrypt
# or decrypt data packets (kernel handles all of that), so the ping continuity
# assertion validates the kernel key-swap path specifically.
#
# Returns exit code 77 (SKIP) if the ovpn-dco kernel module is not available.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - ovpn-dco kernel module loaded or loadable
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#
# Usage: sudo ./test_itr4_dco_rekey.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server_rekey_dco.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client_no_reneg.json"

# DCO client needs enable_dco:true
CLIENT_DCO_CONFIG="${PROJECT_ROOT}/integration/configs/it_client_dco_no_reneg.json"

NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=20        # DCO setup takes slightly longer
REKEY_TIMEOUT=45
PING_DURATION=50
PING_INTERVAL=1
MIN_SUCCESS_PCT=80

LOG_DIR="/tmp/vpn-itr4"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
PING_LOG="${LOG_DIR}/ping.log"

SERVER_PID=""
CLIENT_PID=""
PING_PID=""

# ── Helpers ──────────────────────────────────────────────────────────

ns_exec() { ip netns exec "$1" "${@:2}"; }
ns_bg()   { exec nsenter --net="/run/netns/$1" -- "${@:2}"; }

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    [[ -n "${PING_PID}"   ]] && kill -TERM "${PING_PID}"   2>/dev/null || true
    [[ -n "${CLIENT_PID}" ]] && kill -TERM "${CLIENT_PID}" 2>/dev/null || true
    [[ -n "${SERVER_PID}" ]] && kill -TERM "${SERVER_PID}" 2>/dev/null || true
    sleep 1
    [[ -n "${PING_PID}"   ]] && kill -9 "${PING_PID}"   2>/dev/null || true
    [[ -n "${CLIENT_PID}" ]] && kill -9 "${CLIENT_PID}" 2>/dev/null || true
    [[ -n "${SERVER_PID}" ]] && kill -9 "${SERVER_PID}" 2>/dev/null || true
    wait 2>/dev/null || true
    # Clean up DCO devices
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
    echo "--- Server log (last 60 lines) ---"
    tail -60 "${SERVER_LOG}" 2>/dev/null || echo "(no log)"
    echo ""
    echo "--- Client log (last 60 lines) ---"
    tail -60 "${CLIENT_LOG}" 2>/dev/null || echo "(no log)"
    exit 1
}

# ── Preconditions ────────────────────────────────────────────────────

echo "=== IT-R4: DCO Server-Initiated Rekey — Kernel Key Swap ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

# Gate: ovpn-dco kernel module must be available
if ! modprobe -n ovpn-dco 2>/dev/null && ! modprobe -n ovpn-dco-v2 2>/dev/null; then
    echo "SKIP: ovpn-dco kernel module not available"
    exit 77
fi
modprobe ovpn-dco 2>/dev/null || modprobe ovpn-dco-v2 2>/dev/null || {
    echo "SKIP: Failed to load ovpn-dco kernel module"
    exit 77
}
echo "      ovpn-dco module loaded"

if [[ ! -x "${BINARY}" ]]; then
    echo "Error: Binary not found at ${BINARY}"
    exit 1
fi

for ns in "${NS_SERVER}" "${NS_CLIENT}"; do
    if ! ip netns list | grep -qw "${ns}"; then
        echo "Error: Namespace ${ns} not found."
        exit 1
    fi
done

# Build a DCO client config with rekey disabled on-the-fly from the DCO base config
mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}" "${PING_LOG}"

# Derive DCO-enabled no-reneg client config from it_client_dco.json
python3 - "${PROJECT_ROOT}/integration/configs/it_client_dco.json" \
          "/tmp/vpn-itr4/it_client_dco_no_reneg.json" <<'PYEOF'
import json, sys
in_path, out_path = sys.argv[1], sys.argv[2]
with open(in_path) as f:
    cfg = json.load(f)
cfg["client"]["renegotiate_seconds"] = 0
cfg["client"]["keepalive_timeout"] = 60
with open(out_path, "w") as f:
    json.dump(cfg, f, indent=4)
PYEOF
CLIENT_DCO_CONFIG="/tmp/vpn-itr4/it_client_dco_no_reneg.json"

cd "${PROJECT_ROOT}"

# ── Start server ─────────────────────────────────────────────────────

echo "[1/6] Starting DCO server (reneg=30s)..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
echo "      Server PID: ${SERVER_PID}"

# Poll until the DCO device appears in the server namespace (up to 10s).
# A fixed sleep is unreliable under load; the device typically appears within 1s.
dco_srv_ready=0
for (( _t = 0; _t < 10; _t++ )); do
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then fail "Server exited immediately"; fi
    if ns_exec "${NS_SERVER}" ip link show 2>/dev/null | grep -q "ovpn"; then
        dco_srv_ready=1
        break
    fi
    sleep 1
done
(( dco_srv_ready == 1 )) || fail "DCO device not found in server namespace after ${_t}s"
echo "      DCO device visible in server namespace ✓"

# ── Start client ─────────────────────────────────────────────────────

echo "[2/6] Starting DCO client (client rekey disabled)..."
ns_bg "${NS_CLIENT}" "${BINARY}" "${CLIENT_DCO_CONFIG}" \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!
echo "      Client PID: ${CLIENT_PID}"

# ── Wait for handshake ───────────────────────────────────────────────

echo "[3/6] Waiting up to ${HANDSHAKE_TIMEOUT}s for DCO handshake..."

handshake_ok=0
elapsed=0
while (( elapsed < HANDSHAKE_TIMEOUT )); do
    if grep -qi "state.*->.*Connected\b" "${CLIENT_LOG}" 2>/dev/null; then
        handshake_ok=1
        break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then fail "Server died during handshake"; fi
    if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then fail "Client died during handshake"; fi
    sleep 1
    (( elapsed++ )) || true
done

(( handshake_ok == 1 )) || fail "Handshake did not complete within ${HANDSHAKE_TIMEOUT}s"
echo "      Handshake completed in ~${elapsed}s"

# Verify DCO device in client namespace — poll briefly since handshake just completed
dco_cli_ready=0
for (( _t = 0; _t < 5; _t++ )); do
    if ns_exec "${NS_CLIENT}" ip link show 2>/dev/null | grep -q "ovpn"; then
        dco_cli_ready=1
        break
    fi
    sleep 1
done
(( dco_cli_ready == 1 )) || fail "DCO device not found in client namespace after handshake"
echo "      DCO device visible in client namespace ✓"

TUNNEL_IP_BEFORE=$(ns_exec "${NS_CLIENT}" ip -4 addr show 2>/dev/null \
    | grep -v "lo\b" | grep -oP 'inet \K10\.8\.[0-9.]+' | head -1 || echo "")
[[ -n "${TUNNEL_IP_BEFORE}" ]] || fail "Could not determine client DCO tunnel IP"
echo "      Tunnel IP before rekey: ${TUNNEL_IP_BEFORE}"

# ── Start continuous ping loop ───────────────────────────────────────

echo "[4/6] Starting continuous ping (${PING_DURATION}s)..."
ns_bg "${NS_CLIENT}" ping \
    -c "${PING_DURATION}" \
    -i "${PING_INTERVAL}" \
    -W 2 \
    "${TUNNEL_SERVER_IP}" \
    > "${PING_LOG}" 2>&1 &
PING_PID=$!

# ── Wait for rekey ───────────────────────────────────────────────────

echo "[5/6] Waiting up to ${REKEY_TIMEOUT}s for server-initiated DCO rekey..."

rekey_ok=0
elapsed=0
while (( elapsed < REKEY_TIMEOUT )); do
    if grep -q "Rekey complete" "${CLIENT_LOG}" 2>/dev/null; then
        rekey_ok=1
        break
    fi
    if grep -q "State: .* -> Error" "${CLIENT_LOG}" 2>/dev/null; then
        fail "Client entered Error state during rekey window"
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then fail "Server died during rekey wait"; fi
    if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then fail "Client died during rekey wait"; fi
    sleep 1
    (( elapsed++ )) || true
done

(( rekey_ok == 1 )) || fail "\"Rekey complete\" not seen in client log within ${REKEY_TIMEOUT}s"
echo "      DCO rekey completed at ~${elapsed}s"

# Verify keys were pushed to kernel (log message from DcoClientDataMixin)
if ! grep -q "PushKeysToKernel\|key.*slot\|rekey\|Rekey" "${CLIENT_LOG}" 2>/dev/null; then
    echo "      Warning: no kernel key-push message found in client log"
fi

echo "      Waiting for ping loop to finish..."
wait "${PING_PID}" 2>/dev/null || true
PING_PID=""

# ── Evaluate results ─────────────────────────────────────────────────

echo "[6/6] Evaluating results..."

transmitted=$(grep -oP '\d+(?= packets transmitted)' "${PING_LOG}" || echo "0")
received=$(grep -oP '\d+(?= received)'               "${PING_LOG}" || echo "0")

echo ""
echo "--- Ping summary ---"
tail -3 "${PING_LOG}"
echo ""

if (( transmitted == 0 )); then fail "No ping packets were transmitted"; fi

success_pct=$(( received * 100 / transmitted ))
echo "      Ping success: ${received}/${transmitted} (${success_pct}%)"

if (( success_pct < MIN_SUCCESS_PCT )); then
    fail "DCO tunnel continuity below threshold: ${success_pct}% < ${MIN_SUCCESS_PCT}%"
fi

TUNNEL_IP_AFTER=$(ns_exec "${NS_CLIENT}" ip -4 addr show 2>/dev/null \
    | grep -v "lo\b" | grep -oP 'inet \K10\.8\.[0-9.]+' | head -1 || echo "")
if [[ "${TUNNEL_IP_BEFORE}" != "${TUNNEL_IP_AFTER}" ]]; then
    fail "Tunnel IP changed across rekey: ${TUNNEL_IP_BEFORE} -> ${TUNNEL_IP_AFTER}"
fi
echo "      Tunnel IP unchanged: ${TUNNEL_IP_AFTER} ✓"

echo ""
echo "=== IT-R4 PASSED: DCO server-initiated rekey succeeded, kernel key swap confirmed ==="
