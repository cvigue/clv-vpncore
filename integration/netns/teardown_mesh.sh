#!/bin/bash
# teardown_mesh.sh — Remove mesh integration test namespaces
#
# Usage: sudo ./teardown_mesh.sh

set -euo pipefail

echo "=== Mesh Integration Test: Namespace Teardown ==="

for ns in $(ip netns list 2>/dev/null | awk '/^ns-mesh-/ {print $1}'); do
    ip netns del "$ns" 2>/dev/null && echo "  Deleted $ns" || true
    # Force remove any stray files (in case namespace delete partially failed)
    rm -f "/run/netns/$ns" 2>/dev/null || true
done

echo "=== Teardown complete ==="
