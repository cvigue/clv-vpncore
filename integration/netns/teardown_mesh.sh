#!/bin/bash
# teardown_mesh.sh — Remove mesh integration test namespaces
#
# Usage: sudo ./teardown_mesh.sh

set -euo pipefail

echo "=== Mesh Integration Test: Namespace Teardown ==="

for ns in $(ip netns list 2>/dev/null | awk '/^ns-mesh-/ {print $1}'); do
    ip netns del "$ns" 2>/dev/null && echo "  Deleted $ns" || true
done

echo "=== Teardown complete ==="
