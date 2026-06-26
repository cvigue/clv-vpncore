#!/bin/bash

_PERF_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TUNNEL_SERVER_IP="10.8.0.1"

perf_note() {
    echo "[perf] $*"
}

perf_warn() {
    echo "[perf][warn] $*" >&2
}

perf_error() {
    echo "[perf][error] $*" >&2
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

can_use_netem() {
    command_exists tc || return 1
    tc qdisc show dev lo >/dev/null 2>&1 || return 1
    return 0
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
