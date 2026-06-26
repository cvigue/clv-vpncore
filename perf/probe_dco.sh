#!/bin/bash
# probe_dco.sh — Compare clv vs ovpn DCO server device settings and CPU cost.
#
# Usage: sudo ./perf/probe_dco.sh --client-host vpn-test-0
#
# Runs two iperf3 scenarios (clv server, ovpn server) and for each:
#   - Captures ip link show ovpn-dco0 (txqueuelen, MTU)
#   - Captures ethtool -k ovpn-dco0 (offload features)
#   - Captures perf stat for the server process during iperf
#   - Prints a side-by-side summary
#
# Traffic direction mirrors the main harness:
#   iperf3 server: local, bound to 10.8.0.1 (tunnel IP)
#   iperf3 client: remote (CLIENT_HOST), connects to 10.8.0.1 through tunnel

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"

source "${SCRIPT_DIR}/lib/perf_common.sh"
source "${SCRIPT_DIR}/lib/perf_remote.sh"

CLIENT_HOST=""
IPERF_DURATION=30
DCO_IFACE="ovpn-dco0"
TUNNEL_SERVER_IP="10.8.0.1"
LOG_DIR="/tmp/probe_dco_$$"

usage() {
    echo "Usage: sudo $0 --client-host HOST"
    exit 1
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --client-host) CLIENT_HOST="$2"; shift 2;;
            *) echo "Unknown argument: $1"; usage;;
        esac
    done
    [[ -n "${CLIENT_HOST}" ]] || usage
}

# ── Cleanup ──────────────────────────────────────────────────────────

SERVER_PID=""
IPERF_SRV_PID=""
PERF_PID=""

cleanup() {
    [[ -n "${PERF_PID}" ]]     && kill -TERM "${PERF_PID}"     2>/dev/null || true
    [[ -n "${IPERF_SRV_PID}" ]] && kill -TERM "${IPERF_SRV_PID}" 2>/dev/null || true
    [[ -n "${SERVER_PID}" ]]   && kill -TERM "${SERVER_PID}"   2>/dev/null || true
    remote_sudo "${CLIENT_HOST}" bash -c \
        "'pkill -TERM simple_vpn 2>/dev/null; pkill -TERM openvpn 2>/dev/null; pkill -TERM iperf3 2>/dev/null; true'" \
        2>/dev/null || true
    sleep 1
    ip link del "${DCO_IFACE}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Probe one scenario ───────────────────────────────────────────────
# $1 = label ("clv" or "ovpn")
probe_scenario() {
    local label="$1"
    local out="${LOG_DIR}/${label}"
    mkdir -p "${out}"
    SERVER_PID=""; IPERF_SRV_PID=""; PERF_PID=""

    echo ""
    echo "══ Probing: ${label} server ══════════════════════════════════"

    # -- Load DCO module --
    modprobe ovpn-dco 2>/dev/null || modprobe ovpn-dco-v2 2>/dev/null || true

    # -- Start server --
    if [[ "${label}" == "clv" ]]; then
        "${BUILD_DIR}/demos/simple_vpn" "${PROJECT_ROOT}/perf/configs/server_dco_udp.json" \
            > "${out}/server.log" 2>&1 &
    else
        openvpn --cd "${PROJECT_ROOT}" \
            --config "${PROJECT_ROOT}/perf/configs/server_ovpn_dco_udp.conf" \
            > "${out}/server.log" 2>&1 &
    fi
    SERVER_PID=$!
    sleep 2

    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo "  ERROR: server exited — see ${out}/server.log"
        tail -20 "${out}/server.log"
        SERVER_PID=""
        return 1
    fi

    # -- Capture device settings as soon as ovpn-dco0 appears --
    local waited=0
    while (( waited < 10 )); do
        ip link show "${DCO_IFACE}" >/dev/null 2>&1 && break
        sleep 1; (( waited++ )) || true
    done

    if ip link show "${DCO_IFACE}" >/dev/null 2>&1; then
        echo "  [ovpn-dco0 at startup]"
        ip link show "${DCO_IFACE}" | tee "${out}/iplink_startup.txt"
        ethtool -k "${DCO_IFACE}" > "${out}/ethtool_features.txt" 2>&1 || true
        ethtool -g "${DCO_IFACE}" > "${out}/ethtool_rings.txt"    2>&1 || true
    else
        echo "  WARNING: ${DCO_IFACE} did not appear within 10s"
    fi

    # -- Start client (remote) --
    echo "  Starting ${label} client on ${CLIENT_HOST}..."
    if [[ "${label}" == "clv" ]]; then
        start_remote_client "${CLIENT_HOST}" "client_dco_udp.json" "${REMOTE_DEPLOY_DIR}/client.log"
    else
        start_remote_openvpn "${CLIENT_HOST}" "ovpn_dco_udp.ovpn"
    fi

    # -- Wait for handshake --
    local server_wait_pat
    if [[ "${label}" == "clv" ]]; then
        server_wait_pat='sending PUSH_REPLY|exchange complete|keys derived and installed'
    else
        server_wait_pat='SENT CONTROL.*PUSH_REPLY|Data Channel: cipher'
    fi

    echo "  Waiting for handshake..."
    local hs_wait=0
    while (( hs_wait < 30 )); do
        grep -Eqi "${server_wait_pat}" "${out}/server.log" 2>/dev/null && break
        sleep 1; (( hs_wait++ )) || true
    done

    if grep -Eqi "${server_wait_pat}" "${out}/server.log" 2>/dev/null; then
        echo "  Handshake complete (~${hs_wait}s)"
    else
        echo "  WARNING: handshake pattern not found — continuing anyway"
        tail -5 "${out}/server.log"
    fi

    # Capture device state after handshake (peer is registered in kernel now)
    echo "  [ovpn-dco0 after handshake]"
    ip link show "${DCO_IFACE}" 2>/dev/null | tee "${out}/iplink_after_hs.txt" || true

    # -- Start iperf3 server locally --
    { iperf3 -s -1 -B "${TUNNEL_SERVER_IP}" > "${out}/iperf_server.log" 2>&1 & } 2>/dev/null
    IPERF_SRV_PID=$!
    sleep 1

    # -- perf stat the VPN server process for full iperf duration --
    echo "  Starting perf stat on server pid ${SERVER_PID} for ${IPERF_DURATION}s..."
    perf stat -p "${SERVER_PID}" -- sleep "${IPERF_DURATION}" \
        > "${out}/perf_stat.txt" 2>&1 &
    PERF_PID=$!

    # -- Run iperf3 client remotely through the tunnel --
    echo "  Running iperf3 for ${IPERF_DURATION}s..."
    run_remote_iperf_tcp "${CLIENT_HOST}" "${TUNNEL_SERVER_IP}" \
        "${IPERF_DURATION}" 1 0 "${out}/iperf_client.json" || true

    wait "${PERF_PID}" 2>/dev/null || true; PERF_PID=""

    # -- Final device snapshot --
    ip -s link show "${DCO_IFACE}" 2>/dev/null > "${out}/iplink_final_stats.txt" || true

    # -- Get throughput --
    local bps
    bps=$(python3 -c "
import json
try:
    j = json.load(open('${out}/iperf_client.json'))
    print(f\"{j['end']['sum_received']['bits_per_second']/1e9:.2f}\")
except Exception as e:
    print('N/A')
" 2>/dev/null)
    echo "  Throughput: ${bps} Gbps"
    echo "${bps}" > "${out}/throughput_gbps.txt"

    # -- Teardown --
    kill -TERM "${IPERF_SRV_PID}" 2>/dev/null || true; IPERF_SRV_PID=""
    if [[ "${label}" == "clv" ]]; then
        stop_remote_client "${CLIENT_HOST}"
    else
        stop_remote_openvpn "${CLIENT_HOST}"
    fi
    kill -TERM "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true; SERVER_PID=""
    ip link del "${DCO_IFACE}" 2>/dev/null || true
    sleep 3   # allow kernel to clean up before next scenario

    echo "  Results in ${out}/"
}

# ── Summary ───────────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo "══ SUMMARY ══════════════════════════════════════════════════"
    for label in clv ovpn; do
        local out="${LOG_DIR}/${label}"
        echo ""
        echo "  ── ${label} server ──────────────────────────────────"

        local bps="N/A"
        [[ -f "${out}/throughput_gbps.txt" ]] && bps=$(cat "${out}/throughput_gbps.txt")
        printf "  Throughput:   %s Gbps\n" "${bps}"

        # Device info (after-hs is most representative)
        local f="${out}/iplink_after_hs.txt"
        [[ -f "${f}" ]] || f="${out}/iplink_startup.txt"
        if [[ -f "${f}" ]]; then
            local txqlen mtu
            txqlen=$(grep -oP 'qlen \K[0-9]+' "${f}" 2>/dev/null || echo "?")
            mtu=$(grep -oP 'mtu \K[0-9]+' "${f}" 2>/dev/null || echo "?")
            printf "  txqueuelen:   %s\n" "${txqlen}"
            printf "  mtu:          %s\n" "${mtu}"
        fi

        # ethtool features (selected interesting ones)
        if [[ -f "${out}/ethtool_features.txt" ]]; then
            echo "  ethtool features (non-fixed):"
            grep -v ': fixed' "${out}/ethtool_features.txt" 2>/dev/null \
                | grep -v '^Features' | sed 's/^/    /' || true
        fi

        # perf stat summary
        if [[ -f "${out}/perf_stat.txt" ]]; then
            echo "  perf stat (server, ${IPERF_DURATION}s):"
            grep -E 'task-clock|cycles|instructions|cache-miss|context-switch|cpu-migrat|seconds time' \
                "${out}/perf_stat.txt" 2>/dev/null | sed 's/^/    /' || true
        fi
    done

    echo ""
    echo "  Full results in: ${LOG_DIR}/"
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────────

parse_args "$@"

[[ $(id -u) -eq 0 ]] || { echo "Run as root (sudo)"; exit 1; }

mkdir -p "${LOG_DIR}"
echo "Probe DCO: clv vs ovpn server  |  client=${CLIENT_HOST}  |  out=${LOG_DIR}"

# Verify deploy exists on remote (must have been deployed by a prior perf run)
if ! remote_sudo "${CLIENT_HOST}" test -x "${REMOTE_DEPLOY_DIR}/simple_vpn" 2>/dev/null; then
    echo ""
    echo "WARNING: ${REMOTE_DEPLOY_DIR}/simple_vpn not found on ${CLIENT_HOST}"
    echo "  Run a normal perf scenario first (any clv client scenario) to deploy, then retry."
    echo ""
fi

probe_scenario "clv"
probe_scenario "ovpn"

print_summary
