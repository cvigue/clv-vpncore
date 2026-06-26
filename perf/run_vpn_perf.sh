#!/bin/bash
# run_vpn_perf.sh — VPN performance suite (remote VM execution)
#
# Orchestrates performance measurements across a dev VM (server) and one or
# more remote test VMs (client) connected over a dedicated data network.
# Uses SSH for orchestration and iperf3 for traffic generation.

set -euo pipefail
set +m  # Disable job control to suppress background PID output

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=perf/lib/perf_common.sh
source "${SCRIPT_DIR}/lib/perf_common.sh"
# shellcheck source=perf/lib/perf_remote.sh
source "${SCRIPT_DIR}/lib/perf_remote.sh"

# ── Globals ───────────────────────────────────────────────────────────

DEFAULT_BUILD_DIR="${PROJECT_ROOT}/build"
BUILD_DIR="${DEFAULT_BUILD_DIR}"
RESULTS_ROOT=""
LIST_ONLY=0
SHOW_WARNINGS=0
MEASURE_RTT=0
RUN_TIMESTAMP="$(date +%Y%m%dT%H%M%S)"
IPERF_SECONDS="${IPERF_SECONDS:-20}"
IPERF_UDP_BANDWIDTH="${IPERF_UDP_BANDWIDTH:-0}"
HANDSHAKE_TIMEOUT="${HANDSHAKE_TIMEOUT:-30}"
VERBOSE_PROGRESS=0
CLIENT_HOST=""
SERVER_MODE_OVERRIDE=""
SERVER_IMPL=""

# Optional dimension-like selectors (compat layer over legacy scenario matrices)
AXIS_CIMPL_CSV=""
AXIS_SIMPL_CSV=""
AXIS_DPSRV_CSV=""
AXIS_DPCLT_CSV=""
AXIS_TRANSPORT_CSV=""
AXIS_LAT_CSV=""
AXIS_LOSS_CSV=""
AXIS_TRAFFIC_CSV=""
AXIS_STRMS_CSV=""
AXIS_DIR_CSV=""
AXIS_RXP_CSV=""

# Data-plane IPs (Proxmox bridge)
SERVER_DATA_IP="192.168.50.2"
CLIENT_DATA_IP="192.168.50.10"
NETEM_DEV="enp6s19"

# Tunnel IP
TUNNEL_SERVER_IP="10.8.0.1"

# Run fields (set by main loop from expanded run spec)
CLIENT_IMPL=""
DATAPATH=""
VPN_TRANSPORT=""
TRAFFIC=""
PARALLEL_STREAMS=1
IPERF_REVERSE=0
RXP_BATCH="def"

# Active netem values (set by main loop from run spec)
LAT_MS="0"
LOSS_PCT="0"

# Config path selection (set by resolve_configs)
SERVER_CONFIG=""
CLIENT_CONFIG=""
OVPN_CONFIG=""

# Results
RESULT_ROWS=()
RESULT_JSON_OBJECTS=()
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RUN_DIR=""
SUMMARY_JSON=""

# ── CLI ───────────────────────────────────────────────────────────────

usage() {
    cat <<'EOF'
VPN Performance Suite (Remote VM)

Usage:
  perf/run_vpn_perf.sh --client-host HOST [options]

Options:
    --client-host HOST     Remote test VM hostname or IP (required)
    --list                 Show active axis values and expanded run count
    --simpl CSV            Server impl axis: clv,ovpn (default: clv)
    --cimpl CSV            Client impl axis: clv,ovpn (default: clv,ovpn)
    --dpsrv CSV            Server datapath axis: user,dco (default: user,dco)
    --dpclt CSV            Client datapath axis: user,dco (default: user,dco)
    --transport CSV        VPN transport axis (default: udp)
    --lat CSV              Latency(ms) axis (default: 0)
    --loss CSV             Loss(%) axis (default: 0)
    --traffic CSV          Traffic axis: tcp,udp,udp-<rate>,ping (default: tcp)
                           e.g. tcp,udp-100m,ping  — ping runs an idle RTT measurement (no iperf)
    --ping                 Run concurrent ping during each iperf run; avg loaded RTT
                           fills the RTT/JIT column (use --traffic ping for idle RTT)
    --strms CSV            Stream-count axis (default: 1)
    --dir CSV              Direction axis: fwd,rev,bi (default: fwd)
    --rxp CSV              rx_process_batch axis: non-negative integers or 'def' (default: def)
                           e.g. 0,16,64,128  — 'def' leaves config value unchanged; 0 = all at once
    --verbose-progress     Emit per-step run notes
    --warn                 Print log warning summary after results table
    --build-dir PATH       Build directory (default: build/)
    --results-root PATH    Root directory for performance artifacts
    -t SECONDS             iperf3 duration per scenario (default: 20)
    -b RATE                iperf3 UDP target rate for plain 'udp' traffic (default: 0 = unlimited)
    --help                 Show this help text

Environment overrides:
  IPERF_SECONDS          Same as -t
  IPERF_UDP_BANDWIDTH    Same as -b
  HANDSHAKE_TIMEOUT      Default: 30
EOF
}

parse_args() {
    while (( $# > 0 )); do
        case "$1" in
            --client-host)
                CLIENT_HOST="$2"
                shift 2
                ;;
            --list)
                LIST_ONLY=1
                shift
                ;;
            --matrix|--scenario|--smode)
                perf_error "Legacy option '$1' is no longer supported; use axis flags (--cimpl/--simpl/--dpsrv/--dpclt/--lat/--loss/--strms/--dir)"
                exit 1
                ;;
            --impl)
                perf_error "'--impl' has been renamed to '--cimpl' (client impl); use '--simpl' for server impl"
                exit 1
                ;;
            --cimpl)
                AXIS_CIMPL_CSV="$2"
                shift 2
                ;;
            --simpl)
                AXIS_SIMPL_CSV="$2"
                shift 2
                ;;
            --dpclt)
                AXIS_DPCLT_CSV="$2"
                shift 2
                ;;
            --dpsrv)
                AXIS_DPSRV_CSV="$2"
                shift 2
                ;;
            --transport)
                AXIS_TRANSPORT_CSV="$2"
                shift 2
                ;;
            --lat)
                AXIS_LAT_CSV="$2"
                shift 2
                ;;
            --loss)
                AXIS_LOSS_CSV="$2"
                shift 2
                ;;
            --traffic)
                AXIS_TRAFFIC_CSV="$2"
                shift 2
                ;;
            --strms)
                AXIS_STRMS_CSV="$2"
                shift 2
                ;;
            --dir)
                AXIS_DIR_CSV="$2"
                shift 2
                ;;
            --rxp)
                AXIS_RXP_CSV="$2"
                shift 2
                ;;
            --verbose-progress)
                VERBOSE_PROGRESS=1
                shift
                ;;
            --warn)
                SHOW_WARNINGS=1
                shift
                ;;
            --ping)
                MEASURE_RTT=1
                shift
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

csv_contains_value() {
    local csv="$1" needle="$2"
    [[ -z "${csv}" ]] && return 0

    local item
    IFS=',' read -r -a items <<< "${csv}"
    for item in "${items[@]}"; do
        [[ "${item}" == "${needle}" ]] && return 0
    done
    return 1
}

emit_csv_or_default() {
    local csv="$1" fallback="$2"
    [[ -z "${csv}" ]] && csv="${fallback}"
    local item
    IFS=',' read -r -a items <<< "${csv}"
    for item in "${items[@]}"; do
        echo "${item}"
    done
}

validate_axis_values() {
    local v

    while read -r v; do
        case "${v}" in
            clv|ovpn) ;;
            user|dco)
                perf_error "Invalid --simpl value '${v}'. Allowed: clv,ovpn"
                return 1
                ;;
            *)
                perf_error "Invalid --simpl value '${v}'. Allowed: clv,ovpn"
                return 1
                ;;
        esac
    done < <(emit_csv_or_default "${AXIS_SIMPL_CSV}" "clv")

    while read -r v; do
        case "${v}" in
            clv|ovpn) ;;
            user|dco)
                perf_error "Invalid --cimpl value '${v}' (did you mean --dpclt/--dpsrv?). Allowed: clv,ovpn"
                return 1
                ;;
            *)
                perf_error "Invalid --cimpl value '${v}'. Allowed: clv,ovpn"
                return 1
                ;;
        esac
    done < <(emit_csv_or_default "${AXIS_CIMPL_CSV}" "clv,ovpn")

    while read -r v; do
        case "${v}" in
            user|dco) ;;
            *) perf_error "Invalid --dpsrv value '${v}'. Allowed: user,dco"; return 1 ;;
        esac
    done < <(emit_csv_or_default "${AXIS_DPSRV_CSV}" "user,dco")

    while read -r v; do
        case "${v}" in
            user|dco) ;;
            *) perf_error "Invalid --dpclt value '${v}'. Allowed: user,dco"; return 1 ;;
        esac
    done < <(emit_csv_or_default "${AXIS_DPCLT_CSV}" "user,dco")

    while read -r v; do
        case "${v}" in
            udp|tcp) ;;
            *) perf_error "Invalid --transport value '${v}'. Allowed: udp,tcp"; return 1 ;;
        esac
    done < <(emit_csv_or_default "${AXIS_TRANSPORT_CSV}" "udp")

    while read -r v; do
        [[ "${v}" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
            perf_error "Invalid --lat value '${v}'. Use non-negative numbers in ms"
            return 1
        }
    done < <(emit_csv_or_default "${AXIS_LAT_CSV}" "0")

    while read -r v; do
        [[ "${v}" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
            perf_error "Invalid --loss value '${v}'. Use non-negative percentages"
            return 1
        }
    done < <(emit_csv_or_default "${AXIS_LOSS_CSV}" "0")

    while read -r v; do
        case "${v}" in
            tcp|udp|ping) ;;
            udp-*)
                local bw_part="${v#udp-}"
                [[ "${bw_part}" =~ ^[0-9]+(\.[0-9]+)?[kKmMgGtT]?[bB]?$ ]] || {
                    perf_error "Invalid --traffic value '${v}'. UDP rate must be a number with optional unit (e.g. udp-100m)"
                    return 1
                }
                ;;
            *) perf_error "Invalid --traffic value '${v}'. Allowed: tcp, udp, udp-<rate>, ping (e.g. udp-100m)"; return 1 ;;
        esac
    done < <(emit_csv_or_default "${AXIS_TRAFFIC_CSV}" "tcp")

    while read -r v; do
        [[ "${v}" =~ ^[1-9][0-9]*$ ]] || {
            perf_error "Invalid --strms value '${v}'. Use positive integers"
            return 1
        }
    done < <(emit_csv_or_default "${AXIS_STRMS_CSV}" "1")

    while read -r v; do
        case "${v}" in
            fwd|rev|bi) ;;
            *) perf_error "Invalid --dir value '${v}'. Allowed: fwd,rev,bi"; return 1 ;;
        esac
    done < <(emit_csv_or_default "${AXIS_DIR_CSV}" "fwd")

    while read -r v; do
        case "${v}" in
            def) ;;
            *)
                [[ "${v}" =~ ^[0-9]+$ ]] || {
                    perf_error "Invalid --rxp value '${v}'. Use non-negative integers or 'def'"
                    return 1
                }
                ;;
        esac
    done < <(emit_csv_or_default "${AXIS_RXP_CSV}" "def")

    return 0
}

# ── Config resolution ─────────────────────────────────────────────────

resolve_configs() {
    SERVER_CONFIG=""
    CLIENT_CONFIG=""
    OVPN_CONFIG=""

    local srv_dp="${SERVER_MODE_OVERRIDE:-${DATAPATH}}"

    # Server config: depends on server impl, server datapath, and VPN transport.
    if [[ "${SERVER_IMPL}" == "ovpn" ]]; then
        case "${srv_dp}-${VPN_TRANSPORT}" in
            user-udp)
                SERVER_CONFIG="${PROJECT_ROOT}/perf/configs/server_ovpn_user_udp.conf"
                ;;
            dco-udp)
                SERVER_CONFIG="${PROJECT_ROOT}/perf/configs/server_ovpn_dco_udp.conf"
                ;;
            user-tcp)
                SERVER_CONFIG="${PROJECT_ROOT}/perf/configs/server_ovpn_user_tcp.conf"
                ;;
            *)
                perf_error "Unsupported ovpn server datapath/transport: ${srv_dp}-${VPN_TRANSPORT}"
                return 1
                ;;
        esac
    else
        case "${DATAPATH}-${VPN_TRANSPORT}" in
            user-udp)
                SERVER_CONFIG="${PROJECT_ROOT}/perf/configs/server_user_udp.json"
                ;;
            user-tcp)
                SERVER_CONFIG="${PROJECT_ROOT}/perf/configs/server_user_tcp.json"
                ;;
            dco-udp)
                SERVER_CONFIG="${PROJECT_ROOT}/perf/configs/server_dco_udp.json"
                ;;
            *)
                perf_error "Unsupported transport/datapath: ${DATAPATH}-${VPN_TRANSPORT}"
                return 1
                ;;
        esac
    fi

    # Client configs: always selected by client datapath + VPN transport.
    case "${DATAPATH}-${VPN_TRANSPORT}" in
        user-udp)
            CLIENT_CONFIG="${PROJECT_ROOT}/perf/configs/client_user_udp.json"
            OVPN_CONFIG="${PROJECT_ROOT}/perf/configs/ovpn_user_udp.ovpn"
            ;;
        user-tcp)
            CLIENT_CONFIG="${PROJECT_ROOT}/perf/configs/client_user_tcp.json"
            OVPN_CONFIG="${PROJECT_ROOT}/perf/configs/ovpn_user_tcp.ovpn"
            ;;
        dco-udp)
            CLIENT_CONFIG="${PROJECT_ROOT}/perf/configs/client_dco_udp.json"
            OVPN_CONFIG="${PROJECT_ROOT}/perf/configs/ovpn_dco_udp.ovpn"
            ;;
        *)
            perf_error "Unsupported client transport/datapath: ${DATAPATH}-${VPN_TRANSPORT}"
            return 1
            ;;
    esac
}

is_supported_combo() {
    local simpl="$1"
    local impl="$2"
    local dpsrv="$3"
    local dpclt="$4"
    local transport="$5"

    # TCP transport currently supports only userspace datapaths.
    if [[ "${transport}" == "tcp" ]]; then
        [[ "${dpsrv}" == "user" && "${dpclt}" == "user" ]] || return 1
    fi

    # Reserved for future per-impl/per-transport compatibility checks.
    : "${impl}" "${simpl}"

    return 0
}

cleanup_local_runtime_state() {
    local simple_vpn_bin="${BUILD_DIR}/demos/simple_vpn"
    local pid

    while read -r pid; do
        [[ -n "${pid}" ]] && kill -TERM "${pid}" >/dev/null 2>&1 || true
    done < <(pgrep -f -- "${simple_vpn_bin}" || true)

    while read -r pid; do
        [[ -n "${pid}" ]] && kill -TERM "${pid}" >/dev/null 2>&1 || true
    done < <(pgrep -f -- 'openvpn.*perf/configs/server_ovpn' || true)

    while read -r pid; do
        [[ -n "${pid}" ]] && kill -TERM "${pid}" >/dev/null 2>&1 || true
    done < <(pgrep -f -- 'iperf3 -s -1 -B 10.8.0.1' || true)

    sleep 1

    while read -r pid; do
        [[ -n "${pid}" ]] && kill -9 "${pid}" >/dev/null 2>&1 || true
    done < <(pgrep -f -- "${simple_vpn_bin}" || true)

    while read -r pid; do
        [[ -n "${pid}" ]] && kill -9 "${pid}" >/dev/null 2>&1 || true
    done < <(pgrep -f -- 'openvpn.*perf/configs/server_ovpn' || true)

    while read -r pid; do
        [[ -n "${pid}" ]] && kill -9 "${pid}" >/dev/null 2>&1 || true
    done < <(pgrep -f -- 'iperf3 -s -1 -B 10.8.0.1' || true)

    clear_netem_local "${NETEM_DEV}"

    local dev
    for dev in $(ip -o link show type tun 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1); do
        ip link del "${dev}" 2>/dev/null || true
    done
    for dev in $(ip -d -o link show 2>/dev/null | awk -F': ' '/ovpn-dco/{print $2}' | cut -d'@' -f1); do
        ip link del "${dev}" 2>/dev/null || true
    done
}

# ── Axis expansion ───────────────────────────────────────────────────

list_axes() {
    local vals
    echo "Axis values:"

    vals=$(emit_csv_or_default "${AXIS_SIMPL_CSV}" "clv" | tr '\n' ' ')
    echo "  simpl:     ${vals}"
    vals=$(emit_csv_or_default "${AXIS_CIMPL_CSV}" "clv,ovpn" | tr '\n' ' ')
    echo "  cimpl:     ${vals}"
    vals=$(emit_csv_or_default "${AXIS_DPSRV_CSV}" "user,dco" | tr '\n' ' ')
    echo "  dpsrv:     ${vals}"
    vals=$(emit_csv_or_default "${AXIS_DPCLT_CSV}" "user,dco" | tr '\n' ' ')
    echo "  dpclt:     ${vals}"
    vals=$(emit_csv_or_default "${AXIS_TRANSPORT_CSV}" "udp" | tr '\n' ' ')
    echo "  transport: ${vals}"
    vals=$(emit_csv_or_default "${AXIS_LAT_CSV}" "0" | tr '\n' ' ')
    echo "  lat:       ${vals}"
    vals=$(emit_csv_or_default "${AXIS_LOSS_CSV}" "0" | tr '\n' ' ')
    echo "  loss:      ${vals}"
    vals=$(emit_csv_or_default "${AXIS_TRAFFIC_CSV}" "tcp" | tr '\n' ' ')
    echo "  traffic:   ${vals}"
    vals=$(emit_csv_or_default "${AXIS_STRMS_CSV}" "1" | tr '\n' ' ')
    echo "  strms:     ${vals}"
    vals=$(emit_csv_or_default "${AXIS_DIR_CSV}" "fwd" | tr '\n' ' ')
    echo "  dir:       ${vals}"
    vals=$(emit_csv_or_default "${AXIS_RXP_CSV}" "def" | tr '\n' ' ')
    echo "  rxp:       ${vals}"
}

emit_run_specs() {
    local impl_values=() simpl_values=() dpsrv_values=() dpclt_values=() transport_values=()
    local lat_values=() loss_values=() traffic_values=() strms_values=() dir_values=()

    mapfile -t simpl_values < <(emit_csv_or_default "${AXIS_SIMPL_CSV}" "clv")
    mapfile -t impl_values < <(emit_csv_or_default "${AXIS_CIMPL_CSV}" "clv,ovpn")
    mapfile -t dpsrv_values < <(emit_csv_or_default "${AXIS_DPSRV_CSV}" "user,dco")
    mapfile -t dpclt_values < <(emit_csv_or_default "${AXIS_DPCLT_CSV}" "user,dco")
    mapfile -t transport_values < <(emit_csv_or_default "${AXIS_TRANSPORT_CSV}" "udp")
    mapfile -t lat_values < <(emit_csv_or_default "${AXIS_LAT_CSV}" "0")
    mapfile -t loss_values < <(emit_csv_or_default "${AXIS_LOSS_CSV}" "0")
    mapfile -t traffic_values < <(emit_csv_or_default "${AXIS_TRAFFIC_CSV}" "tcp")
    mapfile -t strms_values < <(emit_csv_or_default "${AXIS_STRMS_CSV}" "1")
    mapfile -t dir_values < <(emit_csv_or_default "${AXIS_DIR_CSV}" "fwd")
    mapfile -t rxp_values < <(emit_csv_or_default "${AXIS_RXP_CSV}" "def")

    local impl dpsrv dpclt xpt lat loss traffic strms dir rxp simpl label
    for simpl in "${simpl_values[@]}"; do
    for impl in "${impl_values[@]}"; do
        for dpsrv in "${dpsrv_values[@]}"; do
            for dpclt in "${dpclt_values[@]}"; do
                for xpt in "${transport_values[@]}"; do
                    if ! is_supported_combo "${simpl}" "${impl}" "${dpsrv}" "${dpclt}" "${xpt}"; then
                        continue
                    fi
                    for lat in "${lat_values[@]}"; do
                        for loss in "${loss_values[@]}"; do
                            for traffic in "${traffic_values[@]}"; do
                                for strms in "${strms_values[@]}"; do
                                    for dir in "${dir_values[@]}"; do
                                        local actual_dirs=()
                                        case "${dir}" in
                                            fwd|rev) actual_dirs=("${dir}") ;;
                                            bi) actual_dirs=(fwd rev) ;;
                                            *) continue ;;
                                        esac

                                        local actual_dir
                                        for actual_dir in "${actual_dirs[@]}"; do
                                            # ping is directionless — only emit the fwd pass
                                            [[ "${traffic}" == "ping" && "${actual_dir}" != "fwd" ]] && continue
                                            [[ "${strms}" != "1" && "${traffic}" != "tcp" ]] && continue

                                            local ovpn_rxp_emitted=0
                                            local dco_rxp_emitted=0
                                            for rxp in "${rxp_values[@]}"; do
                                                # ovpn server ignores rx_process_batch; collapse all rxp values
                                                # into a single run using "def" (emit only the first)
                                                if [[ "${simpl}" == "ovpn" ]]; then
                                                    (( ovpn_rxp_emitted == 1 )) && continue
                                                    rxp="def"
                                                    ovpn_rxp_emitted=1
                                                fi

                                                # DCO-only runs bypass userspace rx path; collapse to one run
                                                if [[ "${dpsrv}" == "dco" && "${dpclt}" == "dco" ]]; then
                                                    (( dco_rxp_emitted == 1 )) && continue
                                                    rxp="def"
                                                    dco_rxp_emitted=1
                                                fi

                                                local emit_dir="${actual_dir}"
                                                [[ "${traffic}" == "ping" ]] && emit_dir="-"

                                                label="${impl}-${dpclt}-${xpt}-${traffic}"
                                                [[ "${actual_dir}" == "rev" ]] && label+="-reverse"
                                                [[ "${strms}" != "1" ]] && label+="-streams${strms}"
                                                [[ "${rxp}" != "def" ]] && label+="-rxp${rxp}"

                                                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                                                    "${label}" "${simpl}" "${impl}" "${dpclt}" "${dpsrv}" "${xpt}" "${traffic}" "${lat}" "${loss}" "${emit_dir}" "${strms}" "${rxp}"
                                            done
                                        done
                                    done
                                done
                            done
                        done
                    done
                done
            done
        done
    done
    done
}

# ── Progress display ──────────────────────────────────────────────────

emit_run_note() {
    if (( VERBOSE_PROGRESS == 1 )); then
        perf_note "$*"
    fi
}

progress_begin_scenario() {
    local index="$1" total="$2" banner="$3"
    if (( VERBOSE_PROGRESS == 1 )); then
        echo
        echo "=== [${index}/${total}] ${banner} ==="
    else
        printf '\r\033[2K=== [%d/%d] %s ===' "${index}" "${total}" "${banner}"
    fi
}

progress_end_for_summary() {
    if (( VERBOSE_PROGRESS == 0 )); then
        printf '\r\033[2K'
        echo
    fi
}

format_progress_banner() {
    local dir="fwd"
    (( IPERF_REVERSE == 1 )) && dir="rev"

    local dpsrv="${SERVER_MODE_OVERRIDE:-${DATAPATH}}"

    local traf_banner="${TRAFFIC}"
    if [[ "${TRAFFIC}" == "udp" && "${IPERF_UDP_BANDWIDTH}" != "0" && -n "${IPERF_UDP_BANDWIDTH}" ]]; then
        traf_banner="udp-${IPERF_UDP_BANDWIDTH}"
    fi

    printf '%s' "simpl=${SERVER_IMPL} cimpl=${CLIENT_IMPL} dpsrv=${dpsrv} dpclt=${DATAPATH} xpt=${VPN_TRANSPORT} lat=${LAT_MS} loss=${LOSS_PCT} traf=${traf_banner} dir=${dir} strms=${PARALLEL_STREAMS} rxp=${RXP_BATCH}"
}

# ── Metadata capture ─────────────────────────────────────────────────

capture_metadata() {
    local metadata_file="$1"
    local scenario="$2"

    {
        echo "scenario=${scenario}"
        echo "server_impl=${SERVER_IMPL}"
        echo "client_impl=${CLIENT_IMPL}"
        echo "datapath=${DATAPATH}"
        echo "vpn_transport=${VPN_TRANSPORT}"
        echo "traffic=${TRAFFIC}"
        echo "lat_ms=${LAT_MS}"
        echo "loss_pct=${LOSS_PCT}"
        echo "parallel_streams=${PARALLEL_STREAMS}"
        echo "reverse_mode=${IPERF_REVERSE}"
        echo "rx_process_batch=${RXP_BATCH}"
        echo "iperf_seconds=${IPERF_SECONDS}"
        echo "server_mode_override=${SERVER_MODE_OVERRIDE}"
        echo "client_host=${CLIENT_HOST}"
        echo "server_data_ip=${SERVER_DATA_IP}"
        echo "client_data_ip=${CLIENT_DATA_IP}"
        echo "netem_dev=${NETEM_DEV}"
        echo "host_tcp_congestion_control=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
        echo "host_default_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
        echo "host_tcp_rmem=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null || echo unknown)"
        echo "host_tcp_wmem=$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null || echo unknown)"
        echo "host_rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null || echo unknown)"
        echo "host_wmem_max=$(sysctl -n net.core.wmem_max 2>/dev/null || echo unknown)"
    } > "${metadata_file}"
}

# ── Result recording ──────────────────────────────────────────────────

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
    local reason_safe="${reason:-n/a}"

    local dpsrv="${SERVER_MODE_OVERRIDE:-${DATAPATH}}"

    local traf_display="${TRAFFIC}"
    if [[ "${TRAFFIC}" == "udp" && "${IPERF_UDP_BANDWIDTH}" != "0" && -n "${IPERF_UDP_BANDWIDTH}" ]]; then
        traf_display="udp-${IPERF_UDP_BANDWIDTH}"
    fi

    local dir="fwd"
    (( IPERF_REVERSE == 1 )) && dir="rev"
    [[ "${TRAFFIC}" == "ping" ]] && dir="-"
    local strms="${PARALLEL_STREAMS}"

    local row
    printf -v row '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
        "${scenario}" "${status}" "${SERVER_IMPL}" "${CLIENT_IMPL}" "${DATAPATH}" "${VPN_TRANSPORT}" \
        "${traf_display}" "${LAT_MS}" "${LOSS_PCT}" "${handshake_seconds}" "${throughput_bps}" \
        "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}" "${reason_safe}" \
        "${scenario_dir}" "${dpsrv}" "${dir}" "${strms}" "${RXP_BATCH}"
    RESULT_ROWS+=("${row}")

    RESULT_JSON_OBJECTS+=("{\"scenario\":\"$(json_escape "${scenario}")\",\"status\":\"$(json_escape "${status}")\",\"client_impl\":\"$(json_escape "${CLIENT_IMPL}")\",\"datapath\":\"$(json_escape "${DATAPATH}")\",\"vpn_transport\":\"$(json_escape "${VPN_TRANSPORT}")\",\"traffic\":\"$(json_escape "${traf_display}")\",\"dir\":\"$(json_escape "${dir}")\",\"strms\":\"$(json_escape "${strms}")\",\"rxp_batch\":\"$(json_escape "${RXP_BATCH}")\",\"lat_ms\":\"$(json_escape "${LAT_MS}")\",\"loss_pct\":\"$(json_escape "${LOSS_PCT}")\",\"handshake_seconds\":\"$(json_escape "${handshake_seconds}")\",\"throughput_bps\":\"$(json_escape "${throughput_bps}")\",\"transfer_bytes\":\"$(json_escape "${transfer_bytes}")\",\"retransmits\":\"$(json_escape "${retransmits}")\",\"jitter_ms\":\"$(json_escape "${jitter_ms}")\",\"lost_percent\":\"$(json_escape "${lost_percent}")\",\"reason\":\"$(json_escape "${reason_safe}")\",\"artifacts_dir\":\"$(json_escape "${scenario_dir}")\"}" )
}

write_summary_files() {
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

# ── Core scenario execution ───────────────────────────────────────────

run_scenario() {
    local scenario="$1"
    local scenario_dir="$2"
    local server_log="${scenario_dir}/server.log"
    local client_log="${scenario_dir}/client.log"
    local iperf_server_log="${scenario_dir}/iperf_server.log"
    local iperf_client_json="${scenario_dir}/iperf_client.json"
    local metadata_file="${scenario_dir}/metadata.env"
    local server_pid=""
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

    cleanup_scenario() {
        # Remote cleanup
        cleanup_remote "${CLIENT_HOST}" "${CLIENT_DATA_IP}"
        # Local cleanup
        [[ -n "${iperf_server_pid:-}" ]] && kill -TERM "${iperf_server_pid}" >/dev/null 2>&1 || true
        [[ -n "${server_pid:-}" ]] && kill -TERM "${server_pid}" >/dev/null 2>&1 || true
        cleanup_local_runtime_state
        wait >/dev/null 2>&1 || true
    }
    trap cleanup_scenario RETURN

    # ── Validate & resolve ────────────────────────────────────────────

    cleanup_local_runtime_state

    if ! resolve_configs; then
        reason="unsupported config combination"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 1
    fi

    # ── Skip checks ───────────────────────────────────────────────────

    if [[ "${CLIENT_IMPL}" == "ovpn" ]]; then
        if ! remote_exec "${CLIENT_HOST}" 'command -v openvpn || test -x /usr/sbin/openvpn' >/dev/null 2>&1; then
            status="skip"
            reason="openvpn not installed on ${CLIENT_HOST}"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 77
        fi
    fi

    if [[ "${DATAPATH}" == "dco" ]]; then
        if ! remote_sudo "${CLIENT_HOST}" modprobe -n ovpn-dco 2>/dev/null && \
           ! remote_sudo "${CLIENT_HOST}" modprobe -n ovpn-dco-v2 2>/dev/null; then
            status="skip"
            reason="ovpn-dco kernel module unavailable on ${CLIENT_HOST}"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 77
        fi
        remote_sudo "${CLIENT_HOST}" modprobe ovpn-dco 2>/dev/null || \
            remote_sudo "${CLIENT_HOST}" modprobe ovpn-dco-v2 2>/dev/null || true
    fi

    if [[ "${SERVER_IMPL}" == "ovpn" ]]; then
        if ! command -v openvpn >/dev/null 2>&1 && ! [[ -x /usr/sbin/openvpn ]]; then
            status="skip"
            reason="openvpn not installed locally (required for simpl=ovpn)"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 77
        fi
        if [[ "${SERVER_MODE_OVERRIDE:-${DATAPATH}}" == "dco" ]]; then
            if ! modprobe -n ovpn-dco 2>/dev/null && ! modprobe -n ovpn-dco-v2 2>/dev/null; then
                status="skip"
                reason="ovpn-dco kernel module unavailable locally (required for simpl=ovpn dpsrv=dco)"
                record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
                return 77
            fi
        fi
    fi

    if [[ "${LAT_MS}" != "0" || "${LOSS_PCT}" != "0" ]] && ! can_use_netem; then
        status="skip"
        reason="tc netem unavailable on server"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 77
    fi

    if { [[ "${SERVER_IMPL}" != "ovpn" ]] && [[ -n "${SERVER_MODE_OVERRIDE}" || "${RXP_BATCH}" != "def" ]]; } || \
       { [[ "${CLIENT_IMPL}" == "clv" && "${DATAPATH}" == "user" ]] && [[ "${RXP_BATCH}" != "def" ]]; }; then
        if ! command_exists jq; then
            status="skip"
            reason="jq not installed (required for config overrides)"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 77
        fi
    fi

    # ── Apply config overrides ────────────────────────────────────────

    if [[ "${SERVER_IMPL}" != "ovpn" ]] && \
       [[ -n "${SERVER_MODE_OVERRIDE}" || "${RXP_BATCH}" != "def" ]]; then
        local patched_server="${scenario_dir}/server_patched.json"
        cp "${SERVER_CONFIG}" "${patched_server}"

        if [[ -n "${SERVER_MODE_OVERRIDE}" ]]; then
            local dco_val
            [[ "${SERVER_MODE_OVERRIDE}" == "dco" ]] && dco_val=true || dco_val=false
            emit_run_note "Patching server enable_dco=${dco_val}"
            jq --argjson dco "${dco_val}" '.performance.enable_dco = $dco' \
                "${patched_server}" > "${patched_server}.tmp"
            mv "${patched_server}.tmp" "${patched_server}"
        fi

        if [[ "${RXP_BATCH}" != "def" ]]; then
            emit_run_note "Patching server rx_process_batch=${RXP_BATCH}"
            jq --argjson rxp "${RXP_BATCH}" '.performance.rx_process_batch = $rxp' \
                "${patched_server}" > "${patched_server}.tmp"
            mv "${patched_server}.tmp" "${patched_server}"
        fi

        SERVER_CONFIG="${patched_server}"
    fi

    # Patch client config when the client is a clv userspace node and any
    # performance field differs from the baked-in JSON default.
    # DCO clients bypass the userspace RX path so rx_process_batch has no
    # effect there; skip patching to avoid misleading config files.
    if [[ "${CLIENT_IMPL}" == "clv" && "${DATAPATH}" == "user" ]] && \
       [[ "${RXP_BATCH}" != "def" ]]; then
        local patched_client="${scenario_dir}/client_patched.json"
        cp "${CLIENT_CONFIG}" "${patched_client}"

        if [[ "${RXP_BATCH}" != "def" ]]; then
            emit_run_note "Patching client rx_process_batch=${RXP_BATCH}"
            jq --argjson rxp "${RXP_BATCH}" '.performance.rx_process_batch = $rxp' \
                "${patched_client}" > "${patched_client}.tmp"
            mv "${patched_client}.tmp" "${patched_client}"
        fi

        CLIENT_CONFIG="${patched_client}"
    fi

    capture_metadata "${metadata_file}" "${scenario}"

    # ── Deploy to remote ──────────────────────────────────────────────

    emit_run_note "Deploying to ${CLIENT_HOST}"
    if ! deploy_to_remote "${CLIENT_HOST}" "${BUILD_DIR}" "${PROJECT_ROOT}"; then
        reason="deploy to remote failed"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 1
    fi

    # If we created a patched client config, push it directly
    if [[ "${CLIENT_CONFIG}" == "${scenario_dir}/"* ]]; then
        remote_copy_to "${CLIENT_HOST}" "${CLIENT_CONFIG}" "${REMOTE_DEPLOY_DIR}/configs/_client_override.json"
    fi

    # ── Apply netem ───────────────────────────────────────────────────

    if [[ "${LAT_MS}" != "0" || "${LOSS_PCT}" != "0" ]]; then
        emit_run_note "Applying netem: lat=${LAT_MS}ms loss=${LOSS_PCT}%"
        if ! apply_netem_local "${NETEM_DEV}" "${LAT_MS}" "${LOSS_PCT}"; then
            reason="failed to apply netem"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 1
        fi
    fi

    # ── Start server (local) ──────────────────────────────────────────

    emit_run_note "Starting ${SERVER_IMPL} server"
    cd "${PROJECT_ROOT}"

    if [[ "${SERVER_IMPL}" == "ovpn" ]]; then
        # Load DCO module locally if ovpn server is using DCO
        if [[ "${SERVER_MODE_OVERRIDE:-${DATAPATH}}" == "dco" ]]; then
            modprobe ovpn-dco 2>/dev/null || modprobe ovpn-dco-v2 2>/dev/null || true
        fi
        { openvpn --cd "${PROJECT_ROOT}" --config "${SERVER_CONFIG}" > "${server_log}" 2>&1 & } 2>/dev/null
    else
        # Load DCO module locally if needed
        if [[ "${SERVER_MODE_OVERRIDE}" == "dco" ]] || \
           jq -e '.performance.enable_dco == true' "${SERVER_CONFIG}" >/dev/null 2>&1; then
            modprobe ovpn-dco 2>/dev/null || modprobe ovpn-dco-v2 2>/dev/null || true
        fi
        { "${BUILD_DIR}/demos/simple_vpn" "${SERVER_CONFIG}" > "${server_log}" 2>&1 & } 2>/dev/null
    fi
    server_pid=$!
    sleep 2
    if ! kill -0 "${server_pid}" >/dev/null 2>&1; then
        reason="${SERVER_IMPL} server exited during startup"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 1
    fi

    # ── Start client (remote) ─────────────────────────────────────────

    emit_run_note "Starting ${CLIENT_IMPL} client on ${CLIENT_HOST}"
    local remote_client_config
    if [[ "${CLIENT_CONFIG}" == "${scenario_dir}/"* ]]; then
        remote_client_config="_client_override.json"
    else
        remote_client_config="$(basename "${CLIENT_CONFIG}")"
    fi

    if [[ "${CLIENT_IMPL}" == "clv" ]]; then
        start_remote_client "${CLIENT_HOST}" "${remote_client_config}" "${REMOTE_DEPLOY_DIR}/client.log"
    else
        local ovpn_basename
        ovpn_basename="$(basename "${OVPN_CONFIG}")"
        start_remote_openvpn "${CLIENT_HOST}" "${ovpn_basename}"
    fi

    # ── Wait for handshake ────────────────────────────────────────────

    local wait_pattern
    local server_wait_pattern
    local client_wait_pattern
    if [[ "${SERVER_IMPL}" == "ovpn" ]]; then
        server_wait_pattern='SENT CONTROL.*PUSH_REPLY|Data Channel: cipher'
    else
        server_wait_pattern='sending PUSH_REPLY|exchange complete|keys derived and installed'
    fi
    if [[ "${CLIENT_IMPL}" == "clv" ]]; then
        client_wait_pattern='Client connected|State:.*Connected'
    else
        client_wait_pattern='Initialization Sequence Completed'
    fi

    emit_run_note "Waiting for handshake"
    handshake_start=$(date +%s)

    # Watch the server log locally for client arrival
    if wait_for_log_pattern "${server_log}" "${server_wait_pattern}" "${HANDSHAKE_TIMEOUT}" "${server_pid}"; then
        handshake_end=$(date +%s)
        handshake_seconds=$(( handshake_end - handshake_start ))
    else
        # Also check the remote client log
        if wait_for_remote_log_pattern "${CLIENT_HOST}" "${REMOTE_DEPLOY_DIR}/client.log" "${client_wait_pattern}" 5; then
            handshake_end=$(date +%s)
            handshake_seconds=$(( handshake_end - handshake_start ))
        else
            reason="handshake timed out"
            collect_remote_log "${CLIENT_HOST}" "${client_log}"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 1
        fi
    fi

    # ── Probe tunnel connectivity ─────────────────────────────────────

    emit_run_note "Probing tunnel route from ${CLIENT_HOST}"
    if ! probe_remote_tunnel "${CLIENT_HOST}" "${TUNNEL_SERVER_IP}" 15; then
        reason="tunnel route unreachable after handshake"
        collect_remote_log "${CLIENT_HOST}" "${client_log}"
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 1
    fi

    # ── Ping-only traffic run ─────────────────────────────────────────

    if [[ "${TRAFFIC}" == "ping" ]]; then
        local ping_log="${scenario_dir}/ping.log"
        emit_run_note "Running idle ping measurement (${IPERF_SECONDS} packets)"
        local ping_summary
        ping_summary="$(run_remote_ping "${CLIENT_HOST}" "${TUNNEL_SERVER_IP}" "${IPERF_SECONDS}" "${ping_log}")" || true
        if [[ -n "${ping_summary}" ]]; then
            # ping_summary: "avg<TAB>min/max"
            local _ping_avg _ping_minmax
            IFS=$'\t' read -r _ping_avg _ping_minmax <<< "${ping_summary}"
            jitter_ms="${_ping_avg}"
            throughput_bps="${_ping_minmax}ms"
        else
            reason="ping measurement failed"
            collect_remote_log "${CLIENT_HOST}" "${client_log}"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 1
        fi
        collect_remote_log "${CLIENT_HOST}" "${client_log}"
        status="pass"
        reason=""
        record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
        return 0
    fi

    # ── Start concurrent ping if requested ───────────────────────────

    if (( MEASURE_RTT == 1 )); then
        emit_run_note "Starting concurrent ping"
        start_remote_bg_ping "${CLIENT_HOST}" "${TUNNEL_SERVER_IP}" "${IPERF_SECONDS}"
    fi

    # ── Start iperf3 server (local) ───────────────────────────────────

    emit_run_note "Starting iperf3 server"
    { iperf3 -s -1 -B "${TUNNEL_SERVER_IP}" > "${iperf_server_log}" 2>&1 & } 2>/dev/null
    iperf_server_pid=$!
    sleep 1

    # ── Run iperf3 client (remote) ────────────────────────────────────

    emit_run_note "Running ${TRAFFIC} traffic through tunnel"
    if [[ "${TRAFFIC}" == "tcp" ]]; then
        if ! run_remote_iperf_tcp "${CLIENT_HOST}" "${TUNNEL_SERVER_IP}" \
                "${IPERF_SECONDS}" "${PARALLEL_STREAMS}" "${IPERF_REVERSE}" \
                "${iperf_client_json}"; then
            reason="iperf3 TCP run failed"
            collect_remote_log "${CLIENT_HOST}" "${client_log}"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 1
        fi
        throughput_bps="$(iperf_tcp_metric "${iperf_client_json}" bits_per_second || true)"
        transfer_bytes="$(iperf_tcp_metric "${iperf_client_json}" bytes || true)"
        retransmits="$(iperf_tcp_metric "${iperf_client_json}" retransmits || true)"
        [[ -n "${retransmits}" ]] || retransmits="0"
    else
        if ! run_remote_iperf_udp "${CLIENT_HOST}" "${TUNNEL_SERVER_IP}" \
                "${IPERF_SECONDS}" "${IPERF_UDP_BANDWIDTH}" "${IPERF_REVERSE}" \
                "${iperf_client_json}"; then
            reason="iperf3 UDP run failed"
            collect_remote_log "${CLIENT_HOST}" "${client_log}"
            record_result "${scenario}" "${status}" "${reason}" "${scenario_dir}" "${handshake_seconds}" "${throughput_bps}" "${transfer_bytes}" "${retransmits}" "${jitter_ms}" "${lost_percent}"
            return 1
        fi
        throughput_bps="$(iperf_udp_metric "${iperf_client_json}" bits_per_second || true)"
        transfer_bytes="$(iperf_udp_metric "${iperf_client_json}" bytes || true)"
        jitter_ms="$(iperf_udp_metric "${iperf_client_json}" jitter_ms || true)"
        lost_percent="$(iperf_udp_metric "${iperf_client_json}" lost_percent || true)"
    fi

    # Collect concurrent ping result (ping has already finished; -w deadline expired)
    if (( MEASURE_RTT == 1 )); then
        local ping_log="${scenario_dir}/ping.log"
        local ping_summary
        ping_summary="$(collect_remote_bg_ping "${CLIENT_HOST}" "${ping_log}")" || true
        if [[ -n "${ping_summary}" ]]; then
            local _ping_avg
            IFS=$'\t' read -r _ping_avg _ <<< "${ping_summary}"
            jitter_ms="${_ping_avg}"
        fi
    fi

    # Collect remote client log
    collect_remote_log "${CLIENT_HOST}" "${client_log}"

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

# ── Result display ────────────────────────────────────────────────────

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
    local c_bold="" c_reset=""
    if [[ -t 1 ]]; then
        c_bold='\033[1m'
        c_reset='\033[0m'
    fi

    echo
    printf "${c_bold}%-5s %-5s %-5s %-5s %-4s %-4s %-5s %-10s %-3s %-5s %-4s %-17s %-4s %-4s %-9s %-9s %s${c_reset}\n" \
        "DPSRV" "DPCLT" "SIMPL" "CIMPL" "XPT" "LAT" "LOSS" "TRAF" "DIR" "STRMS" "RXP" "THROUGHPUT" "HS" "RT" "RTT/JIT" "PKT-LOSS" "NOTES"
    printf '%0.s-' {1..120}; echo

    local row
    for row in "${RESULT_ROWS[@]}"; do
        local fields
        IFS=$'\t' read -r -a fields <<< "${row}"
        local scenario="${fields[0]}"
        local rstatus="${fields[1]}"
        local srvimpl="${fields[2]:-clv}"
        local cimpl="${fields[3]:-clv}"
        local dpclt="${fields[4]:-user}"
        local xpt="${fields[5]:-udp}"
        local traffic="${fields[6]}"
        local lat="${fields[7]}"
        local loss_pct="${fields[8]}"
        local hs="${fields[9]}"
        local bps="${fields[10]}"
        local retrans="${fields[12]}"
        local rtt_jit="${fields[13]}"
        local loss="${fields[14]}"
        local reason="${fields[15]}"
        local dpsrv="${fields[17]:-${fields[4]:-user}}"
        local dir="${fields[18]:-fwd}"
        local strms="${fields[19]:-1}"
        local rxp_batch="${fields[20]:-def}"

        local tput_str
        if [[ "${traffic}" == "ping" ]]; then
            tput_str="${bps}"
        else
            tput_str="$(format_bps "${bps}")"
        fi

        local hs_str="${hs}s"
        [[ "${hs}" == "n/a" || -z "${hs}" ]] && hs_str="-"

        local rt_str="-"
        if [[ "${rstatus}" == "pass" && "${traffic}" == "tcp" && "${retrans}" != "n/a" ]]; then
            rt_str="${retrans}"
        fi

        local notes=""
        local rtt_jit_str="-"
        local pkt_loss_str="-"
        if [[ "${rstatus}" == "pass" && "${traffic}" == udp* ]]; then
            rtt_jit_str="$(awk -v v="${rtt_jit}" 'BEGIN { printf "%.3fms", v+0 }')"
            pkt_loss_str="$(awk -v v="${loss}" 'BEGIN { printf "%.3f%%", v+0 }')"
        elif [[ "${rstatus}" == "pass" && -n "${rtt_jit}" && "${rtt_jit}" != "n/a" ]]; then
            rtt_jit_str="$(awk -v v="${rtt_jit}" 'BEGIN { printf "%.3fms", v+0 }')"
        fi

        if [[ "${rstatus}" != "pass" ]]; then
            notes="[${rstatus^^}] ${reason:0:40}"
        fi

        printf '%-5s %-5s %-5s %-5s %-4s %-4s %-5s %-10s %-3s %-5s %-4s %-17s %-4s %-4s %-9s %-9s %s\n' \
            "${dpsrv}" "${dpclt}" "${srvimpl}" "${cimpl}" "${xpt}" "${lat}" "${loss_pct}" "${traffic}" "${dir}" "${strms}" "${rxp_batch}" "${tput_str}" "${hs_str}" "${rt_str}" "${rtt_jit_str}" "${pkt_loss_str}" "${notes}"
    done
}

print_log_warnings() {
    local warned=0
    local scenario_dir scenario_label

    for scenario_dir in "${RUN_DIR}"/*/; do
        [[ -d "${scenario_dir}" ]] || continue
        scenario_label="$(basename "${scenario_dir}" | sed 's/^[0-9]*_//')"  # strip leading NN_

        local combined_warnings=()
        local log log_label
        for log in "${scenario_dir}/server.log" "${scenario_dir}/client.log"; do
            [[ -f "${log}" ]] || continue
            log_label="$(basename "${log}" .log)"
            local count_msg
            while IFS= read -r count_msg; do
                combined_warnings+=("  ${log_label}: ${count_msg}")
            done < <(grep -i 'warn' "${log}" \
                     | sed 's/^\[[0-9]\{4\}-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9]*\] //' \
                     | sort | uniq -c | sort -rn \
                     | head -5 \
                     | awk '{count=$1; $1=""; sub(/^ /,""); printf "(%dx) %s\n", count, $0}')
        done

        if (( ${#combined_warnings[@]} > 0 )); then
            if (( warned == 0 )); then
                echo
                printf '%0.s-' {1..80}; echo
                echo "Warnings in logs:"
            fi
            warned=1
            echo "  [${scenario_label}]"
            local w
            for w in "${combined_warnings[@]}"; do
                echo "${w}"
            done
        fi
    done
}

# ── Main ──────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    if ! validate_axis_values; then
        exit 1
    fi

    local run_specs=()
    mapfile -t run_specs < <(emit_run_specs)

    if (( LIST_ONLY == 1 )); then
        list_axes
        echo
        echo "Expanded runs: ${#run_specs[@]}"
        exit 0
    fi

    if [[ -z "${CLIENT_HOST}" ]]; then
        perf_error "--client-host is required"
        usage
        exit 1
    fi

    # Need root locally for server TUN/DCO + netem
    if [[ $(id -u) -ne 0 ]]; then
        if command_exists sudo; then
            exec sudo --preserve-env=PATH,IPERF_SECONDS,IPERF_UDP_BANDWIDTH,HANDSHAKE_TIMEOUT \
                bash "$0" "$@"
        fi
        perf_error "Root or sudo required for server TUN/netem"
        exit 1
    fi

    BUILD_DIR="$(cd "${BUILD_DIR}" && pwd)"
    RESULTS_ROOT="${RESULTS_ROOT:-${BUILD_DIR}/perf-results}"
    mkdir -p "${RESULTS_ROOT}"
    RESULTS_ROOT="$(cd "${RESULTS_ROOT}" && pwd)"
    RUN_DIR="${RESULTS_ROOT}/${RUN_TIMESTAMP}"
    SUMMARY_JSON="${RUN_DIR}/summary.json"
    mkdir -p "${RUN_DIR}"

    cd "${PROJECT_ROOT}"

    if [[ ! -x "${BUILD_DIR}/demos/simple_vpn" ]]; then
        perf_error "simple_vpn not found at ${BUILD_DIR}/demos/simple_vpn"
        exit 1
    fi

    if ! command_exists iperf3; then
        perf_error "iperf3 not installed locally"
        exit 1
    fi

    # ── Pre-flight checks ─────────────────────────────────────────────

    if (( VERBOSE_PROGRESS == 1 )); then
        perf_note "Pre-flight: checking SSH to ${CLIENT_HOST}"
    fi
    if ! preflight_check_remote "${CLIENT_HOST}"; then
        exit 1
    fi

    # Clean up any leftover state from interrupted runs
    if (( VERBOSE_PROGRESS == 1 )); then
        perf_note "Pre-flight: cleaning remote state"
    fi
    cleanup_remote "${CLIENT_HOST}" "${CLIENT_DATA_IP}"

    if (( VERBOSE_PROGRESS == 1 )); then
        perf_note "Results directory: ${RUN_DIR}"
    fi

    if ((${#run_specs[@]} == 0)); then
        perf_error "No runs selected after applying filters"
        exit 1
    fi

    local spec index=1 rc
    local iperf_udp_bw_base="${IPERF_UDP_BANDWIDTH}"
    for spec in "${run_specs[@]}"; do
        local label iperf_dir strms traffic_raw banner
        IFS=$'\t' read -r label SERVER_IMPL CLIENT_IMPL DATAPATH SERVER_MODE_OVERRIDE VPN_TRANSPORT traffic_raw LAT_MS LOSS_PCT iperf_dir strms RXP_BATCH <<< "${spec}"

        if [[ "${traffic_raw}" == udp-* ]]; then
            TRAFFIC="udp"
            IPERF_UDP_BANDWIDTH="${traffic_raw#udp-}"
        else
            TRAFFIC="${traffic_raw}"
            IPERF_UDP_BANDWIDTH="${iperf_udp_bw_base}"
        fi

        [[ "${iperf_dir}" == "rev" ]] && IPERF_REVERSE=1 || IPERF_REVERSE=0
        PARALLEL_STREAMS="${strms}"

        local scenario_dir dir_label
        dir_label="${label}"
        [[ "${LAT_MS}" != "0" || "${LOSS_PCT}" != "0" ]] && dir_label+="-lat${LAT_MS}-loss${LOSS_PCT}"
        scenario_dir=$(printf '%s/%02d_%s' "${RUN_DIR}" "${index}" "${dir_label}")
        mkdir -p "${scenario_dir}"

        banner="$(format_progress_banner)"
        progress_begin_scenario "${index}" "${#run_specs[@]}" "${banner}"
        if run_scenario "${label}" "${scenario_dir}"; then
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
    if (( SHOW_WARNINGS == 1 )); then
        print_log_warnings
    fi

    local total=$(( PASS_COUNT + FAIL_COUNT + SKIP_COUNT ))
    echo
    printf '  Passed: %d  Failed: %d  Skipped: %d  (%d total)\n' \
        "${PASS_COUNT}" "${FAIL_COUNT}" "${SKIP_COUNT}" "${total}"
    printf '  iperf duration: %ds\n' "${IPERF_SECONDS}"
    echo "  JSON: ${SUMMARY_JSON}"
    echo

    if (( FAIL_COUNT > 0 )); then
        exit 1
    fi
}

main "$@"
