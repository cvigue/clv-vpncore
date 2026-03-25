#!/bin/bash
# setup_vpn.sh — Create network-namespace topology for VPN integration tests.
#
# Topology:
#   ns-vpn-bridge
#     └── br0
#           ├── veth-br-srv ←→ veth-srv (10.99.0.1/24)   [ns-vpn-server]
#           ├── veth-br-c0  ←→ veth-c0  (10.99.0.10/24)  [ns-vpn-client-0]
#           ├── veth-br-c1  ←→ veth-c1  (10.99.0.11/24)  [ns-vpn-client-1]
#           └── ...
#
# Usage: sudo ./setup_vpn.sh [NUM_CLIENTS]   (default: 1)
#
# Requires: root / CAP_NET_ADMIN, iproute2, bridge-utils (or iproute2 bridge)

set -euo pipefail

NUM_CLIENTS="${1:-1}"

NS_BRIDGE="ns-vpn-bridge"
NS_SERVER="ns-vpn-server"

BRIDGE_DEV="br0"
SERVER_IP="10.99.0.1"
UNDERLAY_CIDR="24"

echo "=== VPN Integration Test: Network Namespace Setup ==="
echo "    Clients: ${NUM_CLIENTS}"

# ── Helper ───────────────────────────────────────────────────────────

ns_exec() { ip netns exec "$1" "${@:2}"; }

# ── Bridge namespace ─────────────────────────────────────────────────

echo "[1] Creating bridge namespace..."
ip netns add "${NS_BRIDGE}"
ns_exec "${NS_BRIDGE}" ip link set lo up
ns_exec "${NS_BRIDGE}" ip link add "${BRIDGE_DEV}" type bridge
ns_exec "${NS_BRIDGE}" ip link set "${BRIDGE_DEV}" up

# ── Server namespace ─────────────────────────────────────────────────

echo "[2] Creating server namespace..."
ip netns add "${NS_SERVER}"
ns_exec "${NS_SERVER}" ip link set lo up

# Create veth pair: veth-br-srv (bridge side) ←→ veth-srv (server side)
ip link add veth-br-srv type veth peer name veth-srv

# Move endpoints into their namespaces
ip link set veth-br-srv netns "${NS_BRIDGE}"
ip link set veth-srv    netns "${NS_SERVER}"

# Attach bridge side to bridge
ns_exec "${NS_BRIDGE}" ip link set veth-br-srv master "${BRIDGE_DEV}"
ns_exec "${NS_BRIDGE}" ip link set veth-br-srv up

# Configure server side
ns_exec "${NS_SERVER}" ip addr add "${SERVER_IP}/${UNDERLAY_CIDR}" dev veth-srv
ns_exec "${NS_SERVER}" ip link set veth-srv up

# Enable IP forwarding in server namespace (needed for VPN routing)
ns_exec "${NS_SERVER}" sysctl -q -w net.ipv4.ip_forward=1

# ── Client namespaces ────────────────────────────────────────────────

for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    NS_CLIENT="ns-vpn-client-${i}"
    CLIENT_IP="10.99.0.$((10 + i))"
    VETH_BR="veth-br-c${i}"
    VETH_CL="veth-c${i}"

    echo "[3.${i}] Creating client-${i} namespace (${CLIENT_IP})..."
    ip netns add "${NS_CLIENT}"
    ns_exec "${NS_CLIENT}" ip link set lo up

    # Create veth pair
    ip link add "${VETH_BR}" type veth peer name "${VETH_CL}"

    # Move into namespaces
    ip link set "${VETH_BR}" netns "${NS_BRIDGE}"
    ip link set "${VETH_CL}" netns "${NS_CLIENT}"

    # Attach bridge side
    ns_exec "${NS_BRIDGE}" ip link set "${VETH_BR}" master "${BRIDGE_DEV}"
    ns_exec "${NS_BRIDGE}" ip link set "${VETH_BR}" up

    # Configure client side
    ns_exec "${NS_CLIENT}" ip addr add "${CLIENT_IP}/${UNDERLAY_CIDR}" dev "${VETH_CL}"
    ns_exec "${NS_CLIENT}" ip link set "${VETH_CL}" up
done

# ── Verify connectivity ─────────────────────────────────────────────

echo "[4] Verifying underlay connectivity..."
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    NS_CLIENT="ns-vpn-client-${i}"
    if ns_exec "${NS_CLIENT}" ping -c 1 -W 2 "${SERVER_IP}" > /dev/null 2>&1; then
        echo "    client-${i} → server: OK"
    else
        echo "    client-${i} → server: FAIL"
        exit 1
    fi
done

echo "=== Namespace setup complete ==="
echo ""
echo "Namespaces created:"
echo "  ${NS_BRIDGE}  — bridge (${BRIDGE_DEV})"
echo "  ${NS_SERVER}  — server (${SERVER_IP}/${UNDERLAY_CIDR})"
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    echo "  ns-vpn-client-${i} — client (10.99.0.$((10 + i))/${UNDERLAY_CIDR})"
done
