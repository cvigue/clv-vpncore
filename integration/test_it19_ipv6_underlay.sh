#!/bin/bash
# test_it19_ipv6_underlay.sh — IT19: IPv6 underlay connectivity (simple_vpn server + client)
#
# Validates external connectivity over IPv6 underlay:
#   - Server reachable on an IPv6 underlay address
#   - Client connects to IPv6 server address using proto=udp (IPv6 resolved from host literal)
#   - Tunnel data path works end-to-end after IPv6 handshake
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN
#   - simple_vpn built at build/demos/simple_vpn
#   - Network namespaces set up via integration/netns/setup_vpn.sh 1
#
# Usage: sudo ./test_it19_ipv6_underlay.sh [PROJECT_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BINARY="${PROJECT_ROOT}/build/demos/simple_vpn"

NS_SERVER="ns-vpn-server"
NS_CLIENT="ns-vpn-client-0"

SERVER_UNDERLAY_IF="veth-srv"
CLIENT_UNDERLAY_IF="veth-c0"

SERVER_UNDERLAY_V6="fd99::1"
CLIENT_UNDERLAY_V6="fd99::10"
UNDERLAY_PREFIX=64

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT=20
PING_COUNT=5
PING_TIMEOUT=3

LOG_DIR="/tmp/vpn-it19"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
SERVER_CONFIG="${LOG_DIR}/it19_server_ipv6.json"
CLIENT_CONFIG="${LOG_DIR}/it19_client_ipv6.json"

SERVER_PID=""
CLIENT_PID=""

# Helpers
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

echo "=== IT19: IPv6 Underlay Connectivity (UDP Client, IPv6 underlay) ==="

if [[ $(id -u) -ne 0 ]]; then
    exec sudo --preserve-env=PATH "$0" "$@"
fi

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
rm -f "${SERVER_LOG}" "${CLIENT_LOG}" "${SERVER_CONFIG}" "${CLIENT_CONFIG}" "${LOG_DIR}/ping.log"

cd "${PROJECT_ROOT}"

# Provision IPv6 addresses on the existing underlay interfaces.
echo "[1/6] Configuring IPv6 underlay addresses..."
ns_exec "${NS_SERVER}" ip -6 addr replace "${SERVER_UNDERLAY_V6}/${UNDERLAY_PREFIX}" dev "${SERVER_UNDERLAY_IF}" nodad
ns_exec "${NS_CLIENT}" ip -6 addr replace "${CLIENT_UNDERLAY_V6}/${UNDERLAY_PREFIX}" dev "${CLIENT_UNDERLAY_IF}" nodad

if ! ns_exec "${NS_CLIENT}" ping -6 -c 1 -W 2 "${SERVER_UNDERLAY_V6}" > /dev/null 2>&1; then
    fail "Client cannot reach server over IPv6 underlay before VPN start"
fi
echo "      Underlay IPv6 reachability: OK"

# Generate dedicated configs for IPv6 underlay connect.
cat > "${SERVER_CONFIG}" <<EOF
{
  "server": {
    "host": "${SERVER_UNDERLAY_V6}",
    "port": 1194,
    "proto": "udp",
    "dev": "tun",
    "dev_node": "/dev/net/tun",
    "keepalive": [10, 60],
    "cipher": "AES-256-GCM",
    "auth": "SHA256",
    "tls_cipher": "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384",
    "keysize": 256,
    "ca_cert": "test_data/certs/ca.crt",
    "tls_crypt_key": "test_data/certs/tls-crypt.key",
    "cert": "test_data/certs/server.crt",
    "key": "test_data/certs/server.key",
    "dh_params": "test_data/certs/dh2048.pem",
    "network": "10.8.0.0/24",
    "bridge_ip": "10.8.0.1",
    "client_dns": ["8.8.8.8"],
    "routes": [],
    "push_routes": true,
    "client_to_client": true,
    "tun_mtu": 1400,
    "client_cert_required": true,
    "username_password": false,
    "max_clients": 10,
    "ping_timer_remote": 30,
    "renegotiate_seconds": 3600
  },
  "performance": {
    "enable_dco": false,
    "socket_recv_buffer": 262144,
    "socket_send_buffer": 262144,
    "batch_size": 64
  },
  "logging": {
    "verbosity": "debug",
    "subsystems": {
      "control": "debug",
      "sessions": "debug"
    }
  }
}
EOF

cat > "${CLIENT_CONFIG}" <<EOF
{
  "client": {
    "server_host": "${SERVER_UNDERLAY_V6}",
    "server_port": 1194,
    "proto": "udp",
    "cipher": "AES-256-GCM",
    "auth": "SHA256",
    "ca_cert": "test_data/certs/ca.crt",
    "tls_crypt_key": "test_data/certs/tls-crypt.key",
    "cert": "test_data/certs/client.crt",
    "key": "test_data/certs/client.key",
    "keepalive_interval": 5,
    "keepalive_timeout": 30,
    "reconnect_delay_seconds": 2,
    "max_reconnect_attempts": 3
  },
  "performance": {
    "enable_dco": false,
    "socket_recv_buffer": 262144,
    "socket_send_buffer": 262144,
    "batch_size": 64
  },
  "logging": {
    "verbosity": "debug",
    "subsystems": {
      "control": "debug",
      "sessions": "debug"
    }
  }
}
EOF

# Start server.
echo "[2/6] Starting server in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${BINARY}" "${SERVER_CONFIG}" > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately"
fi
echo "      Server PID: ${SERVER_PID}"

# Start client.
echo "[3/6] Starting UDP client in ${NS_CLIENT}..."
ns_bg "${NS_CLIENT}" "${BINARY}" "${CLIENT_CONFIG}" > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!
echo "      Client PID: ${CLIENT_PID}"

# Wait for handshake.
echo "[4/6] Waiting up to ${HANDSHAKE_TIMEOUT}s for handshake..."

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

# Verify tunnel data path.
echo "[5/6] Pinging tunnel gateway ${TUNNEL_SERVER_IP} from client..."
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

# Confirm IPv6 underlay is still healthy.
if ! ns_exec "${NS_CLIENT}" ping -6 -c 1 -W 2 "${SERVER_UNDERLAY_V6}" > /dev/null 2>&1; then
    fail "Underlay IPv6 connectivity regressed during test"
fi

echo "[6/6] Results"
echo ""
echo "--- Ping Results ---"
cat "${LOG_DIR}/ping.log"

echo ""
echo "=== IT19 PASSED ==="
echo "    Logs: ${LOG_DIR}/"
