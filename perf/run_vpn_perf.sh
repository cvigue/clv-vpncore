#!/bin/bash
# run_vpn_perf.sh — Explicit VPN performance suite
#
# Separate from default CTest and integration runs. Uses Linux namespaces,
# tc netem, and iperf3 to collect performance metrics across clv and official
# OpenVPN client variants.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=perf/lib/perf_common.sh
source "${SCRIPT_DIR}/lib/perf_common.sh"

DEFAULT_BUILD_DIR="${PROJECT_ROOT}/build"
BUILD_DIR="${DEFAULT_BUILD_DIR}"
RESULTS_ROOT=""
LIST_ONLY=0
SCENARIO_NAME=""
MATRIX_NAME="stage1"
RUN_TIMESTAMP="$(date +%Y%m%dT%H%M%S)"
IPERF_SECONDS="${IPERF_SECONDS:-20}"
IPERF_UDP_BANDWIDTH="${IPERF_UDP_BANDWIDTH:-700M}"
HANDSHAKE_TIMEOUT="${HANDSHAKE_TIMEOUT:-30}"
BASE_SCENARIO=""
PARALLEL_STREAMS=1
IPERF_REVERSE=0
VERBOSE_PROGRESS=0

STAGE1_SCENARIOS=(
    clv-user-udp-clean-tcp
    clv-user-udp-clean-udp
    clv-user-udp-lat20-tcp
    clv-user-udp-lat100-tcp
    clv-user-tcp-clean-tcp
    clv-dco-udp-clean-tcp
    clv-dco-udp-clean-udp
    clv-dco-udp-lat20-tcp
    clv-dco-udp-lat100-tcp
    ovpn-user-udp-clean-tcp
    ovpn-user-udp-clean-udp
    ovpn-user-udp-lat20-tcp
    ovpn-user-udp-lat100-tcp
    ovpn-dco-udp-clean-tcp
    ovpn-dco-udp-clean-udp
    ovpn-dco-udp-lat20-tcp
    ovpn-dco-udp-lat100-tcp
)

STAGE2_HEADROOM_BASE_SCENARIOS=(
    clv-user-udp-clean-tcp
    clv-user-udp-lat20-tcp
    clv-user-udp-lat100-tcp
    clv-dco-udp-clean-tcp
    clv-dco-udp-lat20-tcp
    clv-dco-udp-lat100-tcp
    ovpn-user-udp-clean-tcp
    ovpn-user-udp-lat20-tcp
    ovpn-user-udp-lat100-tcp
    ovpn-dco-udp-clean-tcp
    ovpn-dco-udp-lat20-tcp
    ovpn-dco-udp-lat100-tcp
)

STAGE2_LOSS_SCENARIOS=(
    clv-user-udp-lat100-loss1-tcp
    clv-dco-udp-lat100-loss1-tcp
    ovpn-user-udp-lat100-loss1-tcp
    ovpn-dco-udp-lat100-loss1-tcp
)

RESULT_ROWS=()
RESULT_JSON_OBJECTS=()
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RUN_DIR=""
SUMMARY_TSV=""
SUMMARY_JSON=""

usage() {
    cat <<'EOF'
VPN Performance Suite

Usage:
  perf/run_vpn_perf.sh [options]

Options:
    --list                 Show available scenarios and profiles
    --matrix NAME          Run a named matrix: stage1 or stage2 (default: stage1)
    --verbose-progress     Emit per-step run notes and linefeed scenario banners
  --scenario NAME        Run a single scenario
  --build-dir PATH       Build directory containing demos/simple_vpn
  --results-root PATH    Root directory for performance artifacts
  -t SECONDS             iperf3 duration per scenario (default: 20)
  -b RATE                iperf3 UDP target rate, e.g. 700M (default: 700M)
  --help                 Show this help text

Environment overrides:
  IPERF_SECONDS          Same as -t
  IPERF_UDP_BANDWIDTH    Same as -b
  HANDSHAKE_TIMEOUT      Default: 30
EOF
}

emit_run_note() {
    if (( VERBOSE_PROGRESS == 1 )); then
        perf_note "$*"
    fi
}

progress_begin_scenario() {
    local index="$1"
    local total="$2"
    local scenario="$3"

    if (( VERBOSE_PROGRESS == 1 )); then
        echo
        echo "=== [${index}/${total}] ${scenario} ==="
    else
        printf '\r\033[2K=== [%d/%d] %s ===' "${index}" "${total}" "${scenario}"
    fi
}

progress_end_for_summary() {
    if (( VERBOSE_PROGRESS == 0 )); then
        printf '\r\033[2K'
        echo
    fi
}

emit_matrix_scenarios() {
    local matrix_name="$1"

    case "${matrix_name}" in
        stage1)
            printf '%s\n' "${STAGE1_SCENARIOS[@]}"
            ;;
        stage2)
            local scenario
            for scenario in "${STAGE2_HEADROOM_BASE_SCENARIOS[@]}"; do
                printf '%s\n' "${scenario}-reverse"
                printf '%s\n' "${scenario}-streams4"
                printf '%s\n' "${scenario}-streams8"
            done
            printf '%s\n' "${STAGE2_LOSS_SCENARIOS[@]}"
            ;;
        *)
            return 1
            ;;
    esac
}

print_matrix_scenarios() {
    emit_matrix_scenarios "$1" | sed 's/^/  /'
}

list_scenarios() {
    cat <<EOF
Matrices:
  stage1          Fast baseline comparison matrix (clean, latency, UDP sanity)
  stage2          Headroom and stress matrix (reverse, multi-stream, loss)

Stage 1 scenarios:
$(print_matrix_scenarios stage1)

Stage 2 scenarios:
$(print_matrix_scenarios stage2)

$(list_perf_profiles)
EOF
}

parse_scenario_variant() {
    BASE_SCENARIO="$1"
    PARALLEL_STREAMS=1
    IPERF_REVERSE=0

    while [[ "${BASE_SCENARIO}" =~ -(reverse|streams[0-9]+)$ ]]; do
        local suffix="${BASH_REMATCH[1]}"
        BASE_SCENARIO="${BASE_SCENARIO%-${suffix}}"
        case "${suffix}" in
            reverse)
                IPERF_REVERSE=1
                ;;
            streams*)
                PARALLEL_STREAMS="${suffix#streams}"
                ;;
        esac
    done

    if ! [[ "${PARALLEL_STREAMS}" =~ ^[1-9][0-9]*$ ]]; then
        perf_error "Invalid stream count in scenario: $1"
        return 1
    fi

    return 0
}

capture_transport_metadata() {
    local metadata_file="$1"
    local state_file="$2"
    local scenario="$3"

    {
        echo "scenario=${scenario}"
        echo "base_scenario=${BASE_SCENARIO}"
        echo "matrix_name=${MATRIX_NAME}"
        echo "client_impl=${CLIENT_IMPL}"
        echo "datapath=${DATAPATH}"
        echo "vpn_transport=${VPN_TRANSPORT}"
        echo "traffic=${TRAFFIC}"
        echo "profile=${PROFILE}"
        echo "iperf_seconds=${IPERF_SECONDS}"
        echo "iperf_udp_bandwidth=${IPERF_UDP_BANDWIDTH}"
        echo "parallel_streams=${PARALLEL_STREAMS}"
        echo "reverse_mode=${IPERF_REVERSE}"
        echo "host_tcp_congestion_control=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
        echo "host_default_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
        echo "host_tcp_rmem=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null || echo unknown)"
        echo "host_tcp_wmem=$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null || echo unknown)"
        echo "host_rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null || echo unknown)"
        echo "host_wmem_max=$(sysctl -n net.core.wmem_max 2>/dev/null || echo unknown)"
    } > "${metadata_file}"

    {
        echo "scenario=${scenario}"
        echo "base_scenario=${BASE_SCENARIO}"
        echo "matrix_name=${MATRIX_NAME}"
        echo
        echo "[host sysctl]"
        sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.core.rmem_max net.core.wmem_max 2>/dev/null || true
        echo
        echo "[bridge qdisc ${BRIDGE_SERVER_VETH}]"
        ns_exec "${NS_BRIDGE}" tc qdisc show dev "${BRIDGE_SERVER_VETH}" 2>/dev/null || true
        echo
        echo "[bridge qdisc ${BRIDGE_CLIENT_VETH}]"
        ns_exec "${NS_BRIDGE}" tc qdisc show dev "${BRIDGE_CLIENT_VETH}" 2>/dev/null || true
        echo
        echo "[server links]"
        ns_exec "${NS_SERVER}" ip -br link 2>/dev/null || true
        echo
        echo "[client links]"
        ns_exec "${NS_CLIENT}" ip -br link 2>/dev/null || true
    } > "${state_file}"
}

capture_tcp_socket_snapshot() {
    local snapshot_file="$1"

    {
        echo "[client ss -tin]"
        ns_exec "${NS_CLIENT}" ss -tin 2>/dev/null || true
        echo
        echo "[server ss -tin]"
        ns_exec "${NS_SERVER}" ss -tin 2>/dev/null || true
    } > "${snapshot_file}"
}

parse_args() {
    while (( $# > 0 )); do
        case "$1" in
            --list)
                LIST_ONLY=1
                shift
                ;;
            --matrix)
                MATRIX_NAME="$2"
                shift 2
                ;;
            --verbose-progress)
                VERBOSE_PROGRESS=1
                shift
                ;;
            --scenario)
                SCENARIO_NAME="$2"
                shift 2
                ;;
            --build-dir)
                BUILD_DIR="$2"
                shift 2
                ;;
            --results-root)
                RESULTS_ROOT="$2"
                shift 2
                ;;
            -t)
                IPERF_SECONDS="$2"
                shift 2
                ;;
            -b)
                IPERF_UDP_BANDWIDTH="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                perf_error "Unknown argument: $1"
                usage
                exit 1
                ;;
        esac
    done
}

absolute_path() {
    local path="$1"
    if [[ "${path}" = /* ]]; then
        echo "${path}"
    else
        echo "$(cd "${PROJECT_ROOT}" && mkdir -p "$(dirname "${path}")" >/dev/null 2>&1 && cd "$(dirname "${path}")" && pwd)/$(basename "${path}")"
    fi
}

select_scenarios() {
    if [[ -n "${SCENARIO_NAME}" ]]; then
        echo "${SCENARIO_NAME}"
        return 0
    fi

    case "${MATRIX_NAME}" in
        stage1)
            printf '%s\n' "${STAGE1_SCENARIOS[@]}"
            ;;
        stage2)
            emit_matrix_scenarios stage2
            ;;
        *)
            perf_error "Unknown matrix: ${MATRIX_NAME}"
            exit 1
            ;;
    esac
}

load_scenario() {
    local scenario="$1"
    CLIENT_IMPL=""
    DATAPATH=""
    VPN_TRANSPORT=""
    PROFILE=""
    TRAFFIC=""
    SERVER_CONFIG=""
    CLIENT_CONFIG=""
    OVPN_CONFIG=""

    if ! parse_scenario_variant "${scenario}"; then
        return 1
    fi

    case "${BASE_SCENARIO}" in
        clv-user-udp-clean-tcp)       CLIENT_IMPL=clv;  DATAPATH=user; VPN_TRANSPORT=udp; PROFILE=clean;         TRAFFIC=tcp ;;
        clv-user-udp-clean-udp)       CLIENT_IMPL=clv;  DATAPATH=user; VPN_TRANSPORT=udp; PROFILE=clean;         TRAFFIC=udp ;;
        clv-user-udp-lat20-tcp)       CLIENT_IMPL=clv;  DATAPATH=user; VPN_TRANSPORT=udp; PROFILE=lat20;         TRAFFIC=tcp ;;
        clv-user-udp-lat100-tcp)      CLIENT_IMPL=clv;  DATAPATH=user; VPN_TRANSPORT=udp; PROFILE=lat100;        TRAFFIC=tcp ;;
        clv-user-udp-lat100-loss1-tcp) CLIENT_IMPL=clv; DATAPATH=user; VPN_TRANSPORT=udp; PROFILE=lat100_loss1;  TRAFFIC=tcp ;;
        clv-user-tcp-clean-tcp)       CLIENT_IMPL=clv;  DATAPATH=user; VPN_TRANSPORT=tcp; PROFILE=clean;         TRAFFIC=tcp ;;
        clv-dco-udp-clean-tcp)        CLIENT_IMPL=clv;  DATAPATH=dco;  VPN_TRANSPORT=udp; PROFILE=clean;         TRAFFIC=tcp ;;
        clv-dco-udp-clean-udp)        CLIENT_IMPL=clv;  DATAPATH=dco;  VPN_TRANSPORT=udp; PROFILE=clean;         TRAFFIC=udp ;;
        clv-dco-udp-lat20-tcp)        CLIENT_IMPL=clv;  DATAPATH=dco;  VPN_TRANSPORT=udp; PROFILE=lat20;         TRAFFIC=tcp ;;
        clv-dco-udp-lat100-tcp)       CLIENT_IMPL=clv;  DATAPATH=dco;  VPN_TRANSPORT=udp; PROFILE=lat100;        TRAFFIC=tcp ;;
        clv-dco-udp-lat100-loss1-tcp) CLIENT_IMPL=clv;  DATAPATH=dco;  VPN_TRANSPORT=udp; PROFILE=lat100_loss1;  TRAFFIC=tcp ;;
        ovpn-user-udp-clean-tcp)      CLIENT_IMPL=ovpn; DATAPATH=user; VPN_TRANSPORT=udp; PROFILE=clean;         TRAFFIC=tcp ;;
        ovpn-user-udp-clean-udp)      CLIENT_IMPL=ovpn; DATAPATH=user; VPN_TRANSPORT=udp; PROFILE=clean;         TRAFFIC=udp ;;
        ovpn-user-udp-lat20-tcp)      CLIENT_IMPL=ovpn; DATAPATH=user; VPN_TRANSPORT=udp; PROFILE=lat20;         TRAFFIC=tcp ;;
        ovpn-user-udp-lat100-tcp)     CLIENT_IMPL=ovpn; DATAPATH=user; VPN_TRANSPORT=udp; PROFILE=lat100;        TRAFFIC=tcp ;;
        ovpn-user-udp-lat100-loss1-tcp) CLIENT_IMPL=ovpn; DATAPATH=user; VPN_TRANSPORT=udp; PROFILE=lat100_loss1; TRAFFIC=tcp ;;
        ovpn-dco-udp-clean-tcp)       CLIENT_IMPL=ovpn; DATAPATH=dco;  VPN_TRANSPORT=udp; PROFILE=clean;         TRAFFIC=tcp ;;
        ovpn-dco-udp-clean-udp)       CLIENT_IMPL=ovpn; DATAPATH=dco;  VPN_TRANSPORT=udp; PROFILE=clean;         TRAFFIC=udp ;;
        ovpn-dco-udp-lat20-tcp)       CLIENT_IMPL=ovpn; DATAPATH=dco;  VPN_TRANSPORT=udp; PROFILE=lat20;         TRAFFIC=tcp ;;
        ovpn-dco-udp-lat100-tcp)      CLIENT_IMPL=ovpn; DATAPATH=dco;  VPN_TRANSPORT=udp; PROFILE=lat100;        TRAFFIC=tcp ;;
        ovpn-dco-udp-lat100-loss1-tcp) CLIENT_IMPL=ovpn; DATAPATH=dco; VPN_TRANSPORT=udp; PROFILE=lat100_loss1;  TRAFFIC=tcp ;;
        *)
            perf_error "Unknown scenario: ${scenario}"
            return 1
            ;;
    esac

    if (( IPERF_REVERSE == 1 )) && [[ "${TRAFFIC}" != "tcp" ]]; then
        perf_error "Reverse mode is only supported for TCP scenarios: ${scenario}"
        return 1
    fi

    if (( PARALLEL_STREAMS > 1 )) && [[ "${TRAFFIC}" != "tcp" ]]; then
        perf_error "Multi-stream mode is only supported for TCP scenarios: ${scenario}"
        return 1
    fi

    case "${DATAPATH}-${VPN_TRANSPORT}" in
        user-udp)
            SERVER_CONFIG="${PROJECT_ROOT}/perf/configs/server_user_udp.json"
            CLIENT_CONFIG="${PROJECT_ROOT}/perf/configs/client_user_udp.json"
            OVPN_CONFIG="${PROJECT_ROOT}/perf/configs/ovpn_user_udp.ovpn"
            ;;
        user-tcp)
            SERVER_CONFIG="${PROJECT_ROOT}/perf/configs/server_user_tcp.json"
            CLIENT_CONFIG="${PROJECT_ROOT}/perf/configs/client_user_tcp.json"
            ;;
        dco-udp)
            SERVER_CONFIG="${PROJECT_ROOT}/perf/configs/server_dco_udp.json"
            CLIENT_CONFIG="${PROJECT_ROOT}/perf/configs/client_dco_udp.json"
            OVPN_CONFIG="${PROJECT_ROOT}/perf/configs/ovpn_dco_udp.ovpn"
            ;;
        *)
            perf_error "Unsupported transport/datapath combination in scenario: ${scenario}"
            return 1
            ;;
    esac
}

ensure_root_or_reexec() {
    if [[ $(id -u) -eq 0 ]]; then
        return 0
    fi
    if command_exists sudo; then
        exec sudo --preserve-env=PATH,IPERF_SECONDS,IPERF_UDP_BANDWIDTH,HANDSHAKE_TIMEOUT bash "$0" "$@"
    fi
    perf_warn "Skipping performance run because root or sudo is unavailable."
    exit 0
}

record_result() {
    local scenario="$1"
    local status="$2"
    local reason="$3"
    local scenario_dir="$4"
    local handshake_seconds="$5"
    local throughput_bps="$6"
    local transfer_bytes="$7"
    local retransmits="$8"
    local jitter_ms="$9"
    local lost_percent="${10}"

    local row
    row="${scenario}	${status}	${CLIENT_IMPL}	${DATAPATH}	${VPN_TRANSPORT}	${TRAFFIC}	${PROFILE}	${handshake_seconds}	${throughput_bps}	${transfer_bytes}	${retransmits}	${jitter_ms}	${lost_percent}	${reason}	${scenario_dir}"
    RESULT_ROWS+=("${row}")

    RESULT_JSON_OBJECTS+=("{\"scenario\":\"$(json_escape "${scenario}")\",\"status\":\"$(json_escape "${status}")\",\"client_impl\":\"$(json_escape "${CLIENT_IMPL}")\",\"datapath\":\"$(json_escape "${DATAPATH}")\",\"vpn_transport\":\"$(json_escape "${VPN_TRANSPORT}")\",\"traffic\":\"$(json_escape "${TRAFFIC}")\",\"profile\":\"$(json_escape "${PROFILE}")\",\"handshake_seconds\":\"$(json_escape "${handshake_seconds}")\",\"throughput_bps\":\"$(json_escape "${throughput_bps}")\",\"transfer_bytes\":\"$(json_escape "${transfer_bytes}")\",\"retransmits\":\"$(json_escape "${retransmits}")\",\"jitter_ms\":\"$(json_escape "${jitter_ms}")\",\"lost_percent\":\"$(json_escape "${lost_percent}")\",\"reason\":\"$(json_escape "${reason}")\",\"artifacts_dir\":\"$(json_escape "${scenario_dir}")\"}")
}

write_summary_files() {
    printf 'scenario\tstatus\tclient_impl\tdatapath\tvpn_transport\ttraffic\tprofile\thandshake_seconds\tthroughput_bps\ttransfer_bytes\tretransmits\tjitter_ms\tlost_percent\treason\tartifacts_dir\n' > "${SUMMARY_TSV}"
    if ((${#RESULT_ROWS[@]} > 0)); then
        printf '%b\n' "${RESULT_ROWS[@]}" >> "${SUMMARY_TSV}"
    fi

    {
        echo '{'
        echo "  \"generated_at\": \"${RUN_TIMESTAMP}\","
        echo "  \"results\": ["
        local idx
        for idx in "${!RESULT_JSON_OBJECTS[@]}"; do
            printf '    %s' "${RESULT_JSON_OBJECTS[idx]}"
            if (( idx + 1 < ${#RESULT_JSON_OBJECTS[@]} )); then
                printf ','
            fi
            printf '\n'
        done
        echo '  ]'
        echo '}'
    } > "${SUMMARY_JSON}"
}

run_scenario() {
    local scenario="$1"
    local scenario_dir="$2"
    local server_log="${scenario_dir}/server.log"
    local client_log="${scenario_dir}/client.log"
    local iperf_server_log="${scenario_dir}/iperf_server.log"
    local iperf_client_json="${scenario_dir}/iperf_client.json"
    local iperf_client_stderr="${scenario_dir}/iperf_client.stderr"
    local metadata_file="${scenario_dir}/metadata.env"
    local transport_state_file="${scenario_dir}/transport_state.txt"
    local tcp_snapshot_file="${scenario_dir}/tcp_socket_state.txt"
    local server_pid=""
    local client_pid=""
    local iperf_server_pid=""
    local status="fail"
    local reason=""
    local handshake_seconds="n/a"
    local throughput_bps="n/a"
    local transfer_bytes="n/a"
    local retransmits="n/a"
    local jitter_ms="n/a"
    local lost_percent="n/a"
    local handshake_start=0
    local handshake_end=0
    local wait_rc=0

    cleanup_scenario() {
        [[ -n "${iperf_server_pid:-}" ]] && kill -TERM "${iperf_server_pid}" >/dev/null 2>&1 || true
        [[ -n "${client_pid:-}" ]] && kill -TERM "${client_pid}" >/dev/null 2>&1 || true
        [[ -n "${server_pid:-}" ]] && kill -TERM "${server_pid}" >/dev/null 2>&1 || true
        sleep 1
        [[ -n "${iperf_server_pid:-}" ]] && kill -9 "${iperf_server_pid}" >/dev/null 2>&1 || true
        [[ -n "${client_pid:-}" ]] && kill -9 "${client_pid}" >/dev/null 2>&1 || true
        [[ -n "${server_pid:-}" ]] && kill -9 "${server_pid}" >/dev/null 2>&1 || true
        wait >/dev/null 2>&1 || true
        clear_netem_profile
        clear_tunnel_devices "${NS_SERVER}"
        clear_tunnel_devices "${NS_CLIENT}"
        "${PROJECT_ROOT}/integration/netns/teardown_vpn.sh" 1 >/dev/null 2>&1 || true
    }
    trap cleanup_scenario RETURN

    if ! load_scenario "${scenario}"; then
        reason="unknown scenario definition"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 1
    fi

    if ! command_exists iperf3; then
        status="skip"
        reason="iperf3 not installed"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 77
    fi

    if [[ "${CLIENT_IMPL}" == "ovpn" ]] && ! command_exists openvpn; then
        status="skip"
        reason="openvpn not installed"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 77
    fi

    if [[ "${CLIENT_IMPL}" == "ovpn" && "${DATAPATH}" == "user" ]] && ! openvpn_supports_dco_toggle; then
        status="skip"
        reason="openvpn binary lacks disable-dco support needed for ovpn-user scenarios"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 77
    fi

    if perf_profile_requires_netem "${PROFILE}" && ! can_use_netem; then
        status="skip"
        reason="tc netem unavailable"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 77
    fi

    if [[ "${DATAPATH}" == "dco" ]]; then
        if ! dco_module_available; then
            status="skip"
            reason="ovpn-dco kernel module unavailable"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 77
        fi
        if ! load_dco_module; then
            status="skip"
            reason="failed to load ovpn-dco kernel module"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 77
        fi
    fi

    emit_run_note "Scenario ${scenario}: setting up namespaces"
    if ! "${PROJECT_ROOT}/integration/netns/setup_vpn.sh" 1 > "${scenario_dir}/setup.log" 2>&1; then
        reason="namespace setup failed"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 1
    fi

    if perf_profile_requires_netem "${PROFILE}"; then
        emit_run_note "Scenario ${scenario}: applying profile ${PROFILE}"
        if ! apply_netem_profile "${PROFILE}"; then
            reason="failed to apply tc netem profile"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 1
        fi
    fi

    capture_transport_metadata "${metadata_file}" "${transport_state_file}" "${scenario}"

    emit_run_note "Scenario ${scenario}: starting clv server"
    ns_bg "${NS_SERVER}" "${BUILD_DIR}/demos/simple_vpn" "${SERVER_CONFIG}" > "${server_log}" 2>&1 &
    server_pid=$!
    sleep 2
    if ! kill -0 "${server_pid}" >/dev/null 2>&1; then
        reason="clv server exited during startup"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 1
    fi

    emit_run_note "Scenario ${scenario}: starting client (${CLIENT_IMPL})"
    if [[ "${CLIENT_IMPL}" == "clv" ]]; then
        ns_bg "${NS_CLIENT}" "${BUILD_DIR}/demos/simple_vpn" "${CLIENT_CONFIG}" > "${client_log}" 2>&1 &
    else
        ns_bg "${NS_CLIENT}" openvpn --cd "${PROJECT_ROOT}" --config "${OVPN_CONFIG}" > "${client_log}" 2>&1 &
    fi
    client_pid=$!

    local wait_pattern
    if [[ "${CLIENT_IMPL}" == "clv" ]]; then
        wait_pattern='client connected|state.*connected|connected to server|PUSH_REPLY.*received|tunnel established'
    else
        wait_pattern='Initialization Sequence Completed'
    fi

    emit_run_note "Scenario ${scenario}: waiting for handshake"
    handshake_start=$(date +%s)
    if wait_for_log_pattern "${client_log}" "${wait_pattern}" "${HANDSHAKE_TIMEOUT}" "${server_pid}" "${client_pid}"; then
        handshake_end=$(date +%s)
        handshake_seconds=$(( handshake_end - handshake_start ))
    else
        wait_rc=$?
        case ${wait_rc} in
            1) reason="handshake timed out" ;;
            2) reason="server or client exited during handshake" ;;
            *) reason="handshake failed" ;;
        esac
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 1
    fi

    if [[ "${DATAPATH}" == "dco" ]]; then
        local server_dco client_dco
        server_dco="$(detect_dco_interface "${NS_SERVER}")"
        client_dco="$(detect_dco_interface "${NS_CLIENT}")"
        if [[ -z "${server_dco}" || -z "${client_dco}" ]]; then
            reason="requested DCO scenario did not create DCO interfaces"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 1
        fi
    fi

    emit_run_note "Scenario ${scenario}: starting iperf3 server"
    ns_bg "${NS_SERVER}" iperf3 -s -1 -B "${TUNNEL_SERVER_IP}" > "${iperf_server_log}" 2>&1 &
    iperf_server_pid=$!
    sleep 1

    emit_run_note "Scenario ${scenario}: running ${TRAFFIC} traffic through tunnel"
    if [[ "${TRAFFIC}" == "tcp" ]]; then
        local tcp_args=(iperf3 -c "${TUNNEL_SERVER_IP}" -t "${IPERF_SECONDS}" -J)
        if (( PARALLEL_STREAMS > 1 )); then
            tcp_args+=( -P "${PARALLEL_STREAMS}" )
        fi
        if (( IPERF_REVERSE == 1 )); then
            tcp_args+=( -R )
        fi
        if ! ns_exec "${NS_CLIENT}" "${tcp_args[@]}" > "${iperf_client_json}" 2> "${iperf_client_stderr}"; then
            reason="iperf3 TCP run failed"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 1
        fi
        capture_tcp_socket_snapshot "${tcp_snapshot_file}"
        throughput_bps="$(iperf_tcp_metric "${iperf_client_json}" bits_per_second || true)"
        transfer_bytes="$(iperf_tcp_metric "${iperf_client_json}" bytes || true)"
        retransmits="$(iperf_tcp_metric "${iperf_client_json}" retransmits || true)"
        [[ -n "${retransmits}" ]] || retransmits="0"
    else
        if ! ns_exec "${NS_CLIENT}" iperf3 -u -b "${IPERF_UDP_BANDWIDTH}" -c "${TUNNEL_SERVER_IP}" -t "${IPERF_SECONDS}" -J > "${iperf_client_json}" 2> "${iperf_client_stderr}"; then
            reason="iperf3 UDP run failed"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 1
        fi
        throughput_bps="$(iperf_udp_metric "${iperf_client_json}" bits_per_second || true)"
        transfer_bytes="$(iperf_udp_metric "${iperf_client_json}" bytes || true)"
        jitter_ms="$(iperf_udp_metric "${iperf_client_json}" jitter_ms || true)"
        lost_percent="$(iperf_udp_metric "${iperf_client_json}" lost_percent || true)"
    fi

    [[ -n "${throughput_bps}" ]] || throughput_bps="0"
    [[ -n "${transfer_bytes}" ]] || transfer_bytes="0"
    [[ -n "${jitter_ms}" ]] || jitter_ms="n/a"
    [[ -n "${lost_percent}" ]] || lost_percent="n/a"

    if [[ "${transfer_bytes}" == "0" || "${throughput_bps}" == "0" ]]; then
        reason="iperf3 reported zero transfer"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 1
    fi

    status="pass"
    reason=""
    record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
    return 0
}

format_bps() {
    local bps="$1"
    awk -v b="${bps}" 'BEGIN {
        if (b !~ /^[0-9]/) { print "n/a"; exit }
        if (b+0 >= 1e9) printf "%.2f Gbps", b/1e9
        else if (b+0 >= 1e6) printf "%.1f Mbps", b/1e6
        else if (b+0 >= 1e3) printf "%.0f Kbps", b/1e3
        else          printf "%d bps",   b+0
    }'
}

print_result_table() {
    local c_pass="" c_fail="" c_skip="" c_bold="" c_reset=""
    if [[ -t 1 ]]; then
        c_pass='\033[32m'
        c_fail='\033[31m'
        c_skip='\033[33m'
        c_bold='\033[1m'
        c_reset='\033[0m'
    fi

    echo
    printf "${c_bold}%-44s  %-4s  %-13s  %-4s  %-7s  %s${c_reset}\n" \
        "SCENARIO" "ST" "THROUGHPUT" "HS" "TRAFFIC" "NOTES"
    printf '%0.s-' {1..100}; echo

    local row
    for row in "${RESULT_ROWS[@]}"; do
        local fields
        IFS=$'\t' read -r -a fields <<< "${row}"
        local scenario="${fields[0]}"
        local status="${fields[1]}"
        local traffic="${fields[5]}"
        local hs="${fields[7]}"
        local bps="${fields[8]}"
        local retrans="${fields[10]}"
        local jitter="${fields[11]}"
        local loss="${fields[12]}"
        local reason="${fields[13]}"

        local tput_str
        tput_str="$(format_bps "${bps}")"

        local hs_str="${hs}s"
        [[ "${hs}" == "n/a" || -z "${hs}" ]] && hs_str="-"

        parse_scenario_variant "${scenario}" >/dev/null 2>&1 || true

        local notes=""
        local variant_notes=""
        if (( IPERF_REVERSE == 1 )); then
            variant_notes="reverse"
        elif (( PARALLEL_STREAMS > 1 )); then
            variant_notes="P=${PARALLEL_STREAMS}"
        fi

        if [[ "${status}" == "pass" && "${traffic}" == "udp" ]]; then
            local jitter_r loss_r
            jitter_r="$(awk -v v="${jitter}" 'BEGIN { printf "%.3f", v+0 }')"
            loss_r="$(awk -v v="${loss}" 'BEGIN { printf "%.3f", v+0 }')"
            notes="${jitter_r}ms jitter  ${loss_r}% loss"
        elif [[ "${status}" == "pass" ]]; then
            [[ "${retrans}" != "n/a" && "${retrans}" != "0" ]] && notes="${retrans} retrans"
        else
            notes="${reason:0:58}"
        fi

        if [[ -n "${variant_notes}" ]]; then
            if [[ -n "${notes}" ]]; then
                notes="${variant_notes}  ${notes}"
            else
                notes="${variant_notes}"
            fi
        fi

        local st_colored
        case "${status}" in
            pass) st_colored="${c_pass}PASS${c_reset}" ;;
            fail) st_colored="${c_fail}FAIL${c_reset}" ;;
            skip) st_colored="${c_skip}skip${c_reset}" ;;
            *)    st_colored="${status}" ;;
        esac

        # Print each field; keep color escape codes out of printf width calculations
        printf '%-44s  ' "${scenario:0:44}"
        printf "${st_colored}"
        printf '  %-13s  %-4s  %-7s  %s\n' "${tput_str}" "${hs_str}" "${traffic}" "${notes:0:58}"
    done
}

main() {
    parse_args "$@"

    if (( LIST_ONLY == 1 )); then
        list_scenarios
        exit 0
    fi

    ensure_root_or_reexec "$@"

    BUILD_DIR="$(cd "${BUILD_DIR}" && pwd)"
    RESULTS_ROOT="${RESULTS_ROOT:-${BUILD_DIR}/perf-results}"
    RESULTS_ROOT="$(absolute_path "${RESULTS_ROOT}")"
    RUN_DIR="${RESULTS_ROOT}/${RUN_TIMESTAMP}"
    SUMMARY_TSV="${RUN_DIR}/summary.tsv"
    SUMMARY_JSON="${RUN_DIR}/summary.json"

    mkdir -p "${RUN_DIR}"
    cd "${PROJECT_ROOT}"

    if [[ ! -x "${BUILD_DIR}/demos/simple_vpn" ]]; then
        perf_error "simple_vpn not found at ${BUILD_DIR}/demos/simple_vpn"
        exit 1
    fi

    emit_run_note "Results directory: ${RUN_DIR}"

    local selected=()
    mapfile -t selected < <(select_scenarios)

    local scenario index=1 rc
    for scenario in "${selected[@]}"; do
        local scenario_dir
        scenario_dir=$(printf '%s/%02d_%s' "${RUN_DIR}" "${index}" "${scenario}")
        mkdir -p "${scenario_dir}"

        progress_begin_scenario "${index}" "${#selected[@]}" "${scenario}"
        if run_scenario "${scenario}" "${scenario_dir}"; then
            ((PASS_COUNT++)) || true
        else
            rc=$?
            if (( rc == 77 )); then
                ((SKIP_COUNT++)) || true
            else
                ((FAIL_COUNT++)) || true
            fi
        fi
        ((index++)) || true
    done

    progress_end_for_summary

    write_summary_files
    ln -sfn "${RUN_DIR}" "${RESULTS_ROOT}/latest"

    print_result_table

    local total=$(( PASS_COUNT + FAIL_COUNT + SKIP_COUNT ))
    echo
    printf '  Passed: %d  Failed: %d  Skipped: %d  (%d total)\n' \
        "${PASS_COUNT}" "${FAIL_COUNT}" "${SKIP_COUNT}" "${total}"
    echo "  TSV:  ${SUMMARY_TSV}"
    echo "  JSON: ${SUMMARY_JSON}"
    echo

    if (( FAIL_COUNT > 0 )); then
        exit 1
    fi
}

main "$@"
