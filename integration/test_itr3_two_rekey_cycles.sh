#!/bin/bash
# test_itr3_two_rekey_cycles.sh — IT-R3: Two client-initiated rekey cycles
#
# EXPECTED TO FAIL (XFAIL) until the client-initiated rekey path is fixed.
#
# Exercises the same client-initiated rekey path as IT-R2, but waits for two
# full rekey cycles on the same session. Specifically targets state-accumulation
# bugs that only surface on the second cycle:
#   - rekey_generation_ counter not advancing (stale ClientRekeyLoop coroutines)
#   - client_random_/server_random_ not fully cleared between cycles
#   - key_id_ wrapping or collision
#   - pending DCO key state not reset after first cycle
#
# With client reneg=30 the two cycles fire at ~30s and ~60s. Total test
# duration is ~90s.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#
# Usage: sudo ./test_itr3_two_rekey_cycles.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

SERVER_CONFIG="${PROJECT_ROOT}/integration/configs/it_server.json"
CLIENT_CONFIG="${PROJECT_ROOT}/integration/configs/it_client_rekey.json"

NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=15
# Two client-initiated cycles at 30s each; add margin for second cycle completion.
REKEY2_TIMEOUT=80
PING_DURATION=85
PING_INTERVAL=1
MIN_SUCCESS_PCT=80

LOG_DIR="/tmp/vpn-itr3"
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

echo "=== IT-R3: Two Client-Initiated Rekey Cycles (XFAIL) ==="
echo "    NOTE: This test is expected to fail until the client-initiated rekey"
echo "    path is fixed (InstallDataPathKeys refactor, Step 2 of cca_cleanup)."

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

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}" "${PING_LOG}"
cd "${PROJECT_ROOT}"

# ── Start server + client ────────────────────────────────────────────

echo "[1/6] Starting server (server rekey disabled)..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then fail "Server exited immediately"; fi
echo "      Server PID: ${SERVER_PID}"

echo "[2/6] Starting client (reneg=30s)..."
ns_bg "${NS_CLIENT}" "${BINARY}" "${CLIENT_CONFIG}" \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!
echo "      Client PID: ${CLIENT_PID}"

# ── Wait for handshake ───────────────────────────────────────────────

echo "[3/6] Waiting up to ${HANDSHAKE_TIMEOUT}s for initial handshake..."

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
echo "      Tunnel IP: ${TUNNEL_IP_BEFORE}"

# ── Start continuous ping loop ───────────────────────────────────────

echo "[4/6] Starting continuous ping (${PING_DURATION}s — covers both rekey cycles)..."
ns_bg "${NS_CLIENT}" ping \
    -c "${PING_DURATION}" \
    -i "${PING_INTERVAL}" \
    -W 2 \
    "${TUNNEL_SERVER_IP}" \
    > "${PING_LOG}" 2>&1 &
PING_PID=$!

# ── Wait for two rekey cycles ────────────────────────────────────────

echo "[5/6] Waiting up to ${REKEY2_TIMEOUT}s for two rekey cycles..."

rekey_count=0
elapsed=0
while (( elapsed < REKEY2_TIMEOUT && rekey_count < 2 )); do
    current=$(grep -c "Rekey complete" "${CLIENT_LOG}" 2>/dev/null) || current=0
    if (( current > rekey_count )); then
        rekey_count=${current}
        echo "      Rekey cycle ${rekey_count} completed at ~${elapsed}s"
    fi
    if grep -q "State: .* -> Error" "${CLIENT_LOG}" 2>/dev/null; then
        fail "Client entered Error state during rekey"
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then fail "Server died during rekey wait"; fi
    if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then fail "Client died during rekey wait"; fi
    sleep 1
    (( elapsed++ )) || true
done

(( rekey_count >= 2 )) || fail "Expected 2 rekey cycles; only saw ${rekey_count} within ${REKEY2_TIMEOUT}s"
echo "      Both rekey cycles observed ✓"

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
    fail "Tunnel continuity below threshold across two rekey cycles: ${success_pct}% < ${MIN_SUCCESS_PCT}%"
fi

TUNNEL_IP_AFTER=$(ns_exec "${NS_CLIENT}" ip -4 addr show tun0 2>/dev/null \
    | grep -oP 'inet \K[\d.]+' || echo "")
if [[ "${TUNNEL_IP_BEFORE}" != "${TUNNEL_IP_AFTER}" ]]; then
    fail "Tunnel IP changed: ${TUNNEL_IP_BEFORE} -> ${TUNNEL_IP_AFTER}"
fi
echo "      Tunnel IP unchanged: ${TUNNEL_IP_AFTER} ✓"

echo ""
echo "=== IT-R3 PASSED: two client-initiated rekey cycles succeeded ==="
