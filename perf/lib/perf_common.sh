#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=perf/lib/perf_profiles.sh
source "${SCRIPT_DIR}/perf_profiles.sh"

NS_BRIDGE="ns-vpn-bridge"
NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"
TUNNEL_SERVER_IP="10.8.0.1"
UNDERLAY_SERVER_IP="10.99.0.1"
BRIDGE_SERVER_VETH="veth-br-srv"
BRIDGE_CLIENT_VETH="veth-br-c0"

perf_note() {
    echo "[perf] $*"
}

perf_warn() {
    echo "[perf][warn] $*" >&2
}

perf_error() {
    echo "[perf][error] $*" >&2
}

ns_exec() {
    ip netns exec "$1" "${@:2}"
}

ns_bg() {
    exec nsenter --net="/run/netns/$1" -- "${@:2}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

namespace_exists() {
    ip netns list | grep -qw "$1"
}

can_use_netem() {
    tc qdisc add dev lo root netem delay 0ms >/dev/null 2>&1 || return 1
    tc qdisc del dev lo root >/dev/null 2>&1 || true
    return 0
}

dco_module_available() {
    modprobe -n ovpn-dco >/dev/null 2>&1 || modprobe -n ovpn-dco-v2 >/dev/null 2>&1
}

load_dco_module() {
    modprobe ovpn-dco >/dev/null 2>&1 || modprobe ovpn-dco-v2 >/dev/null 2>&1
}

openvpn_supports_dco_toggle() {
    command_exists openvpn || return 1
    { openvpn --help 2>&1 || true; } | grep -q "disable-dco"
}

clear_tunnel_devices() {
    local ns="$1"
    local dev

    while read -r dev; do
        [[ -n "${dev}" ]] || continue
        ns_exec "${ns}" ip link del "${dev}" >/dev/null 2>&1 || true
    done < <(ns_exec "${ns}" ip -o link show type tun 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1)

    while read -r dev; do
        [[ -n "${dev}" ]] || continue
        ns_exec "${ns}" ip link del "${dev}" >/dev/null 2>&1 || true
    done < <(ns_exec "${ns}" ip -d -o link show 2>/dev/null | awk -F': ' '/ovpn-dco/ {print $2}' | cut -d'@' -f1)
}

clear_netem_profile() {
    ns_exec "${NS_BRIDGE}" tc qdisc del dev "${BRIDGE_SERVER_VETH}" root >/dev/null 2>&1 || true
    ns_exec "${NS_BRIDGE}" tc qdisc del dev "${BRIDGE_CLIENT_VETH}" root >/dev/null 2>&1 || true
}

apply_netem_profile() {
    local profile="$1"
    local args

    args="$(perf_profile_args "${profile}")"
    if [[ -z "${args}" ]]; then
        return 0
    fi

    ns_exec "${NS_BRIDGE}" tc qdisc add dev "${BRIDGE_SERVER_VETH}" root netem ${args}
    ns_exec "${NS_BRIDGE}" tc qdisc add dev "${BRIDGE_CLIENT_VETH}" root netem ${args}
}

wait_for_log_pattern() {
    local log_file="$1"
    local pattern="$2"
    local timeout_seconds="$3"
    shift 3
    local pids=("$@")
    local elapsed=0

    while (( elapsed < timeout_seconds )); do
        if [[ -f "${log_file}" ]] && grep -Eqi "${pattern}" "${log_file}"; then
            return 0
        fi
        local pid
        for pid in "${pids[@]}"; do
            [[ -n "${pid}" ]] || continue
            if ! kill -0 "${pid}" >/dev/null 2>&1; then
                return 2
            fi
        done
        sleep 1
        (( elapsed++ )) || true
    done

    return 1
}

detect_dco_interface() {
    local ns="$1"
    ns_exec "${ns}" ip -d -o link show 2>/dev/null | awk -F': ' '/ovpn-dco/ {print $2; exit}' | cut -d'@' -f1
}

json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/ }"
    echo "${value}"
}

iperf_tcp_metric() {
    local json_file="$1"
    local key="$2"
    awk -v key="\"${key}\"" '
        /"sum_sent"[[:space:]]*:[[:space:]]*{/ { in_block=1; next }
        in_block && /^[[:space:]]*}/ { in_block=0 }
        in_block && index($0, key) {
            line=$0
            gsub(/[[:space:],]/, "", line)
            sub(/^.*:/, "", line)
            print line
            exit
        }
    ' "${json_file}"
}

iperf_udp_metric() {
    local json_file="$1"
    local key="$2"
    awk -v key="\"${key}\"" '
        /"sum"[[:space:]]*:[[:space:]]*{/ { in_block=1; next }
        in_block && /^[[:space:]]*}/ { in_block=0 }
        in_block && index($0, key) {
            line=$0
            gsub(/[[:space:],]/, "", line)
            sub(/^.*:/, "", line)
            print line
            exit
        }
    ' "${json_file}"
}
