#!/bin/bash
# setup_mesh.sh — Create mesh integration test namespace topology
#
# Topology:
#   ns-mesh-bridge: br0 (L2 bridge connecting all nodes)
#   ns-mesh-a (10.99.0.1): Server A — tunnel 10.8.0.0/24
#   ns-mesh-b (10.99.0.2): Server B (10.9.0.0/24) + Client of A
#   ns-mesh-c (10.99.0.3): Client of A + Client of B
#   ns-mesh-d (10.99.0.4): Client of B
#
# Usage: sudo ./setup_mesh.sh

set -euo pipefail

BRIDGE_NS="ns-mesh-bridge"
NODES=(a b c d)
declare -A NODE_IPS=( [a]="10.99.0.1" [b]="10.99.0.2" [c]="10.99.0.3" [d]="10.99.0.4" )
# Nodes running servers need IP forwarding
SERVER_NODES=(a b)

echo "=== Mesh Integration Test: Namespace Setup ==="

# ── 1. Bridge namespace ──────────────────────────────────────────
echo "[1] Creating bridge namespace..."
ip netns add "${BRIDGE_NS}"
ip netns exec "${BRIDGE_NS}" ip link add br0 type bridge
ip netns exec "${BRIDGE_NS}" ip link set br0 up

# ── 2. Node namespaces ───────────────────────────────────────────
for name in "${NODES[@]}"; do
    ns="ns-mesh-${name}"
    node_ip="${NODE_IPS[$name]}"
    echo "[2.${name}] Creating node-${name} namespace (${node_ip})..."

    ip netns add "${ns}"

    # Veth pair: bridge side ↔ node side
    ip link add "veth-br-${name}" type veth peer name "veth-${name}"
    ip link set "veth-br-${name}" netns "${BRIDGE_NS}"
    ip link set "veth-${name}" netns "${ns}"

    # Bridge side: attach to br0
    ip netns exec "${BRIDGE_NS}" ip link set "veth-br-${name}" master br0
    ip netns exec "${BRIDGE_NS}" ip link set "veth-br-${name}" up

    # Node side: configure IP and bring up
    ip netns exec "${ns}" ip addr add "${node_ip}/24" dev "veth-${name}"
    ip netns exec "${ns}" ip link set "veth-${name}" up
    ip netns exec "${ns}" ip link set lo up
done

# ── 3. Enable IP forwarding on server nodes ──────────────────────
for name in "${SERVER_NODES[@]}"; do
    ns="ns-mesh-${name}"
    ip netns exec "${ns}" sysctl -qw net.ipv4.ip_forward=1
done

# ── 4. Verify underlay connectivity ──────────────────────────────
echo "[3] Verifying underlay connectivity..."
for name in "${NODES[@]}"; do
    ns="ns-mesh-${name}"
    for peer in "${NODES[@]}"; do
        [[ "$name" == "$peer" ]] && continue
        peer_ip="${NODE_IPS[$peer]}"
        if ip netns exec "${ns}" ping -c 1 -W 1 -q "${peer_ip}" &>/dev/null; then
            echo "    node-${name} → node-${peer}: OK"
        else
            echo "    node-${name} → node-${peer}: FAIL"
            exit 1
        fi
    done
done

echo "=== Mesh namespace setup complete ==="
echo ""
echo "Namespaces created:"
for name in "${NODES[@]}"; do
    echo "  ns-mesh-${name}  — node (${NODE_IPS[$name]}/24)"
done
