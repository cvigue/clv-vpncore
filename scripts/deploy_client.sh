#!/bin/bash
# Deploy simple_vpn client to a remote test machine.
#
# Usage: ./scripts/deploy_client.sh user@host:path [server_ip]
#
# Examples:
#   ./scripts/deploy_client.sh test@vpn-test-0:~/client
#   ./scripts/deploy_client.sh test@vpn-test-0:~/client 10.0.0.5
#
# Copies the binary, client config, and all referenced certs.
# If server_ip is provided, patches server_host in the deployed config.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 user@host:path [server_ip]"
    exit 1
fi

DEST="$1"
SERVER_IP="${2:-}"

# Parse user@host and remote path from the destination
HOST="${DEST%%:*}"
RPATH="${DEST#*:}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY="$PROJECT_ROOT/build/demos/simple_vpn"

if [[ ! -x "$BINARY" ]]; then
    echo "Error: $BINARY not found or not executable. Build first."
    exit 1
fi

# Collect files referenced by the client config
CONFIG="$PROJECT_ROOT/configs/client_config.json"
CERTS=(
    "$PROJECT_ROOT/test_data/certs/ca.crt"
    "$PROJECT_ROOT/test_data/certs/tls-crypt.key"
    "$PROJECT_ROOT/test_data/certs/client.crt"
    "$PROJECT_ROOT/test_data/certs/client.key"
)

for f in "$CONFIG" "${CERTS[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "Error: Missing $f"
        exit 1
    fi
done

echo "Deploying to $DEST ..."

# Create remote directory structure
ssh "$HOST" "mkdir -p $RPATH/certs"

# Copy binary
scp -q "$BINARY" "$HOST:$RPATH/simple_vpn"

# Copy certs
scp -q "${CERTS[@]}" "$HOST:$RPATH/certs/"

# Generate a deployed config with local cert paths and optional server_ip patch
TMPCONFIG=$(mktemp)
trap 'rm -f "$TMPCONFIG"' EXIT

sed 's|test_data/certs/|certs/|g' "$CONFIG" > "$TMPCONFIG"

if [[ -n "$SERVER_IP" ]]; then
    sed -i "s|\"server_host\":.*|\"server_host\": \"$SERVER_IP\",|" "$TMPCONFIG"
fi

scp -q "$TMPCONFIG" "$HOST:$RPATH/client_config.json"

echo "Done. On $HOST:"
echo "  cd $RPATH && sudo ./simple_vpn client_config.json"
