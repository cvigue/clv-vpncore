#!/bin/bash
# perf_remote.sh — SSH-based remote execution layer for the VPN perf harness.
#
# Provides functions to deploy, launch, collect, and clean up VPN client and
# iperf3 processes on a remote test VM over SSH.  All orchestration traffic
# uses the management network; VPN underlay traffic uses the data network.

# ── Defaults (overridable by the orchestrator) ───────────────────────

REMOTE_DEPLOY_DIR="/tmp/clv-perf"
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5)

# When the harness runs under sudo, SSH must run as the original invoking
# user so that ~/.ssh/config and keys are available.
_SSH_AS_USER="${SUDO_USER:-}"

# Wrap an SSH/SCP/rsync command so it executes as the original user.
# If we are root via sudo, use "sudo -H -u <original_user> ...".
_as_ssh_user() {
    if [[ -n "${_SSH_AS_USER}" && $(id -u) -eq 0 ]]; then
        sudo -H -u "${_SSH_AS_USER}" "$@"
    else
        "$@"
    fi
}

# ── SSH / SCP wrappers ───────────────────────────────────────────────

remote_exec() {
    local host="$1"; shift
    _as_ssh_user ssh "${SSH_OPTS[@]}" "${host}" "$@"
}

remote_sudo() {
    local host="$1"; shift
    _as_ssh_user ssh "${SSH_OPTS[@]}" "${host}" sudo "$@"
}

remote_copy_to() {
    local host="$1" src="$2" dst="$3"
    _as_ssh_user scp "${SSH_OPTS[@]}" -q "${src}" "${host}:${dst}"
}

remote_copy_from() {
    local host="$1" src="$2" dst="$3"
    _as_ssh_user scp "${SSH_OPTS[@]}" -q "${host}:${src}" "${dst}"
}

# ── Pre-flight ────────────────────────────────────────────────────────

preflight_check_remote() {
    local host="$1"

    if ! remote_exec "${host}" true 2>/dev/null; then
        perf_error "Cannot SSH to ${host} (as ${_SSH_AS_USER:-$(whoami)})"
        return 1
    fi

    if ! remote_sudo "${host}" true 2>/dev/null; then
        perf_error "Cannot sudo on ${host} — passwordless sudo required"
        return 1
    fi

    if ! remote_exec "${host}" command -v iperf3 >/dev/null 2>&1; then
        perf_error "iperf3 not found on ${host}"
        return 1
    fi

    if ! remote_exec "${host}" command -v rsync >/dev/null 2>&1; then
        perf_error "rsync not found on ${host} — install with: sudo apt install rsync"
        return 1
    fi

    return 0
}



# ── Deploy ────────────────────────────────────────────────────────────

deploy_to_remote() {
    local host="$1"
    local build_dir="$2"
    local project_root="$3"

    remote_exec "${host}" mkdir -p "${REMOTE_DEPLOY_DIR}" 2>/dev/null

    _as_ssh_user rsync -az --delete \
        -e "ssh ${SSH_OPTS[*]}" \
        "${build_dir}/demos/simple_vpn" \
        "${host}:${REMOTE_DEPLOY_DIR}/" || { perf_error "rsync binary failed"; return 1; }

    _as_ssh_user rsync -az --delete \
        -e "ssh ${SSH_OPTS[*]}" \
        "${project_root}/test_data/certs/" \
        "${host}:${REMOTE_DEPLOY_DIR}/certs/" || { perf_error "rsync certs failed"; return 1; }

    _as_ssh_user rsync -az --delete \
        -e "ssh ${SSH_OPTS[*]}" \
        "${project_root}/perf/configs/" \
        "${host}:${REMOTE_DEPLOY_DIR}/configs/" || { perf_error "rsync configs failed"; return 1; }
}

# ── Process management ────────────────────────────────────────────────

start_remote_client() {
    local host="$1"
    local config_basename="$2"
    local log_file="$3"
    shift 3
    # Any remaining args are extra flags

    # The config references cert paths relative to working dir.
    # We run from REMOTE_DEPLOY_DIR and patch cert paths to be relative to that.
    remote_sudo "${host}" bash -c "'
        cd ${REMOTE_DEPLOY_DIR}
        # Remap test_data/certs/ → certs/ in a temp config
        sed \"s|test_data/certs/|certs/|g\" configs/${config_basename} > /tmp/_clv_client.json
        nohup ./simple_vpn /tmp/_clv_client.json > ${REMOTE_DEPLOY_DIR}/client.log 2>&1 &
        echo \$! >/dev/null
    '" 2>/dev/null
}

stop_remote_client() {
    local host="$1"
    remote_sudo "${host}" pkill -f "simple_vpn.*_clv_client" 2>/dev/null || true
    remote_sudo "${host}" pkill -f "simple_vpn" 2>/dev/null || true
    sleep 1
    remote_sudo "${host}" pkill -9 -f "simple_vpn" 2>/dev/null || true
}

start_remote_openvpn() {
    local host="$1"
    local ovpn_basename="$2"

    remote_sudo "${host}" bash -c "'
        cd ${REMOTE_DEPLOY_DIR}
        sed \"s|test_data/certs/|certs/|g\" configs/${ovpn_basename} > /tmp/_clv_ovpn.conf
        nohup /usr/sbin/openvpn --cd ${REMOTE_DEPLOY_DIR} --config /tmp/_clv_ovpn.conf > ${REMOTE_DEPLOY_DIR}/client.log 2>&1 &
        echo \$! >/dev/null
    '" 2>/dev/null
}

stop_remote_openvpn() {
    local host="$1"
    remote_sudo "${host}" pkill -f openvpn 2>/dev/null || true
    sleep 1
    remote_sudo "${host}" pkill -9 -f openvpn 2>/dev/null || true
}

run_remote_iperf_tcp() {
    local host="$1"
    local tunnel_ip="$2"
    local duration="$3"
    local streams="$4"
    local reverse="$5"
    local output_json="$6"

    local args=(-c "${tunnel_ip}" -t "${duration}" -J)
    if (( streams > 1 )); then
        args+=(-P "${streams}")
    fi
    if (( reverse == 1 )); then
        args+=(-R)
    fi

    remote_exec "${host}" iperf3 "${args[@]}" > "${output_json}" 2>/dev/null
}

run_remote_iperf_udp() {
    local host="$1"
    local tunnel_ip="$2"
    local duration="$3"
    local bandwidth="$4"
    local reverse="$5"
    local output_json="$6"

    local extra_flags=()
    (( reverse == 1 )) && extra_flags+=(-R)

    remote_exec "${host}" iperf3 -u -b "${bandwidth}" -c "${tunnel_ip}" -t "${duration}" \
        "${extra_flags[@]}" -J \
        > "${output_json}" 2>/dev/null
}

run_remote_ping() {
    local host="$1"
    local tunnel_ip="$2"
    local count="$3"   # number of ping packets
    local output_file="$4"

    remote_exec "${host}" ping -c "${count}" -q "${tunnel_ip}" > "${output_file}" 2>/dev/null
    # Parse: "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms"
    # Emit: "avg<TAB>min/max" e.g. "4.321\t2.1/8.7"
    awk '/rtt min/ { split($4, a, "/"); printf "%s\t%s/%s", a[2], a[1], a[3] }' "${output_file}"
}

start_remote_bg_ping() {
    local host="$1"
    local tunnel_ip="$2"
    local duration="$3"   # wall-clock deadline in seconds
    # -w = deadline; -i 0.2 = 5 pps for dense sampling; -q = quiet summary only.
    # Runs as the SSH user (ping is setuid); log written to a fixed temp path.
    remote_exec "${host}" bash -c \
        "'nohup ping -w ${duration} -i 0.2 -q ${tunnel_ip} > /tmp/clv_ping_concurrent.log 2>&1 &'" 2>/dev/null
}

collect_remote_bg_ping() {
    local host="$1"
    local output_file="$2"
    remote_exec "${host}" cat /tmp/clv_ping_concurrent.log > "${output_file}" 2>/dev/null || true
    # Emit: "avg<TAB>min/max" e.g. "4.321\t2.1/8.7"
    awk '/rtt min/ { split($4, a, "/"); printf "%s\t%s/%s", a[2], a[1], a[3] }' "${output_file}"
}

wait_for_remote_log_pattern() {
    local host="$1"
    local remote_log="$2"
    local pattern="$3"
    local timeout_seconds="$4"
    local elapsed=0

    while (( elapsed < timeout_seconds )); do
        if remote_exec "${host}" grep -Eqi "'${pattern}'" "${remote_log}" 2>/dev/null; then
            return 0
        fi
        sleep 1
        (( elapsed++ )) || true
    done
    return 1
}

collect_remote_log() {
    local host="$1"
    local local_dest="$2"
    # The client log is owned by root (started via remote_sudo), so plain SCP
    # as the SSH user cannot read it.  Use sudo cat on the remote side instead.
    remote_sudo "${host}" cat "${REMOTE_DEPLOY_DIR}/client.log" > "${local_dest}" 2>/dev/null || true
}

probe_remote_tunnel() {
    local host="$1"
    local tunnel_ip="$2"
    local timeout="$3"
    local elapsed=0

    while (( elapsed < timeout )); do
        if remote_exec "${host}" ping -c 1 -W 1 -q "${tunnel_ip}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        (( elapsed++ )) || true
    done
    return 1
}

cleanup_remote() {
    local host="$1"
    local data_ip="${2:-}"
    stop_remote_client "${host}"
    stop_remote_openvpn "${host}"
    remote_sudo "${host}" pkill -f iperf3 2>/dev/null || true
    remote_exec "${host}" pkill ping 2>/dev/null || true
    # Clean up tunnel devices
    remote_sudo "${host}" bash -c "'
        for dev in \$(ip -o link show type tun 2>/dev/null | awk -F\": \" \"{print \\\$2}\" | cut -d@ -f1); do
            ip link del \"\$dev\" 2>/dev/null || true
        done
        for dev in \$(ip -d -o link show 2>/dev/null | awk -F\": \" \"/ovpn-dco/{print \\\$2}\" | cut -d@ -f1); do
            ip link del \"\$dev\" 2>/dev/null || true
        done
    '" 2>/dev/null || true
    # Restore the data-plane subnet route — a DCO tunnel may have replaced it
    if [[ -n "${data_ip}" ]]; then
        local cidr="${data_ip%.*}.0/24"
        remote_sudo "${host}" bash -c "'
            if ! ip route show \"${cidr}\" | grep -q \"${cidr}\"; then
                dev=\$(ip -4 -o addr show to \"${data_ip}\" 2>/dev/null | awk \"{print \\\$2}\" | head -1)
                if [[ -n \"\$dev\" ]]; then
                    ip route add \"${cidr}\" dev \"\$dev\" src \"${data_ip}\" 2>/dev/null || true
                fi
            fi
        '" 2>/dev/null || true
    fi
}

# ── Netem on local server NIC ─────────────────────────────────────────

apply_netem_local() {
    local dev="$1"
    local lat_ms="$2"
    local loss_pct="$3"
    # limit: enough for 2 Gbps * 30ms / 1500B ≈ 5000 packets; prevents qdisc tail-drop
    # from masking VPN behaviour when running high-rate UDP reverse at nonzero latency.
    local args="delay ${lat_ms}ms limit 8000"
    [[ "${loss_pct}" != "0" ]] && args+=" loss ${loss_pct}%"
    tc qdisc replace dev "${dev}" root netem ${args}
}

clear_netem_local() {
    local dev="$1"
    tc qdisc del dev "${dev}" root 2>/dev/null || true
}
