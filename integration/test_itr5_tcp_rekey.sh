#!/bin/bash
# test_itr5_tcp_rekey.sh — IT-R5: Server-initiated rekey over TCP transport
#
# Validates that the TCP code path handles renegotiation correctly. The TCP
# channel uses coroutine single-packet I/O with SetTransport wiring (rather
# than the UDP raw-socket FD path), so it exercises a distinct code path
# through AttachTransport and InstallDataPathKeys.
#
# Failure modes caught beyond IT-R1:
#   - SetTransport pointer becoming stale after rekey (TCP channel re-wiring)
#   - TcpToTunLoop / TunToTcpLoop pausing or stalling during key install
#   - TCP length-prefix framing corruption during key transition
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#
# Usage: sudo ./test_itr5_tcp_rekey.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server_rekey_tcp.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client_tcp_no_reneg.json"

NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=15
REKEY_TIMEOUT=45
PING_DURATION=50
PING_INTERVAL=1
MIN_SUCCESS_PCT=80

LOG_DIR="/tmp/vpn-itr5"
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
    echo "--- Server log (last 60 lines) ---"
    tail -60 "${SERVER_LOG}" 2>/dev/null || echo "(no log)"
    echo ""
    echo "--- Client log (last 60 lines) ---"
    tail -60 "${CLIENT_LOG}" 2>/dev/null || echo "(no log)"
    exit 1
}

# ── Preconditions ────────────────────────────────────────────────────

echo "=== IT-R5: TCP Server-Initiated Rekey — Tunnel Continuity ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

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

# Build TCP client config with rekey disabled from existing TCP client config
mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}" "${PING_LOG}"

python3 - <<'PYEOF'
import json
with open("integration/configs/it_client_tcp.json") as f:
    cfg = json.load(f)
cfg["client"]["renegotiate_seconds"] = 0
cfg["client"]["keepalive_timeout"] = 60
with open("/tmp/vpn-itr5/it_client_tcp_no_reneg.json", "w") as f:
    json.dump(cfg, f, indent=4)
PYEOF
CLIENT_CONFIG="/tmp/vpn-itr5/it_client_tcp_no_reneg.json"

cd "${PROJECT_ROOT}"

# ── Start server ─────────────────────────────────────────────────────

echo "[1/6] Starting TCP server (reneg=30s)..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then fail "Server exited immediately"; fi

if ! ns_exec "${NS_SERVER}" ss -tlnp 2>/dev/null | grep -q ":1194 "; then
    echo "      Warning: TCP listener not detected on :1194 yet"
fi
echo "      Server PID: ${SERVER_PID}"

# ── Start client ─────────────────────────────────────────────────────

echo "[2/6] Starting TCP client (client rekey disabled)..."
ns_bg "${NS_CLIENT}" "${BINARY}" "${CLIENT_CONFIG}" \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!
echo "      Client PID: ${CLIENT_PID}"

# ── Wait for handshake ───────────────────────────────────────────────

echo "[3/6] Waiting up to ${HANDSHAKE_TIMEOUT}s for TCP handshake..."

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
sleep 1

TUNNEL_IP_BEFORE=$(ns_exec "${NS_CLIENT}" ip -4 addr show tun0 2>/dev/null \
    | grep -oP 'inet \K[\d.]+' || echo "")
[[ -n "${TUNNEL_IP_BEFORE}" ]] || fail "Could not determine client tunnel IP"
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

echo "[5/6] Waiting up to ${REKEY_TIMEOUT}s for server-initiated TCP rekey..."

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
echo "      TCP rekey completed at ~${elapsed}s"

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
    fail "TCP tunnel continuity below threshold: ${success_pct}% < ${MIN_SUCCESS_PCT}%"
fi

TUNNEL_IP_AFTER=$(ns_exec "${NS_CLIENT}" ip -4 addr show tun0 2>/dev/null \
    | grep -oP 'inet \K[\d.]+' || echo "")
if [[ "${TUNNEL_IP_BEFORE}" != "${TUNNEL_IP_AFTER}" ]]; then
    fail "Tunnel IP changed across rekey: ${TUNNEL_IP_BEFORE} -> ${TUNNEL_IP_AFTER}"
fi
echo "      Tunnel IP unchanged: ${TUNNEL_IP_AFTER} ✓"

echo ""
echo "=== IT-R5 PASSED: TCP server-initiated rekey succeeded, tunnel continuous ==="
