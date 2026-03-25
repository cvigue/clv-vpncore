#!/bin/bash
# teardown_vpn.sh — Destroy all VPN integration test namespaces.
#
# Deleting a namespace automatically cleans up all veth pairs and
# bridge ports owned by that namespace.
#
# Usage: sudo ./teardown_vpn.sh [NUM_CLIENTS]   (default: 1)

set -euo pipefail

NUM_CLIENTS="${1:-1}"

NS_BRIDGE="ns-vpn-bridge"
NS_SERVER="ns-vpn-server"

echo "=== VPN Integration Test: Namespace Teardown ==="

# Kill any VPN processes running in the namespaces
for ns in "${NS_SERVER}" $(seq -f "ns-vpn-client-%.0f" 0 $(( NUM_CLIENTS - 1 ))); do
    if ip netns list | grep -qw "${ns}"; then
        # Kill all processes in the namespace
        ip netns pids "${ns}" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    fi
done

# Brief pause for process cleanup
sleep 0.5

# Delete client namespaces
for i in $(seq 0 $(( NUM_CLIENTS - 1 ))); do
    ns="ns-vpn-client-${i}"
    if ip netns list | grep -qw "${ns}"; then
        ip netns delete "${ns}"
        echo "  Deleted ${ns}"
    fi
done

# Delete server namespace
if ip netns list | grep -qw "${NS_SERVER}"; then
    ip netns delete "${NS_SERVER}"
    echo "  Deleted ${NS_SERVER}"
fi

# Delete bridge namespace (also destroys br0 and all veth-br-* endpoints)
if ip netns list | grep -qw "${NS_BRIDGE}"; then
    ip netns delete "${NS_BRIDGE}"
    echo "  Deleted ${NS_BRIDGE}"
fi

echo "=== Teardown complete ==="
