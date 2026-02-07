#!/bin/bash
# Test large certificate fragmentation and windowing
# This verifies that 4096-bit RSA certificates work with the control channel

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Large Certificate Fragmentation Test ===${NC}"
echo ""

# Check if certs exist
if [ ! -f "../test_data/certs/ca_large.crt" ]; then
    echo -e "${RED}Error: Large certificates not found!${NC}"
    echo "Run: cd test_data/certs && ./gen_large_certs.sh"
    exit 1
fi

# Show cert sizes
echo "Certificate sizes:"
echo "  CA:     $(wc -c < ../test_data/certs/ca_large.crt) bytes"
echo "  Server: $(wc -c < ../test_data/certs/server_large.crt) bytes"
echo "  Client: $(wc -c < ../test_data/certs/client_large.crt) bytes"
echo ""

# Check if we need sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run with sudo (for TUN device access)${NC}"
    echo "Usage: sudo ./test_large_certs.sh"
    exit 1
fi

echo -e "${GREEN}Starting server with large certificates (DEBUG logging)...${NC}"
echo "Watch for these log messages:"
echo "  - 'TLS response size: N bytes' (should be ~5-6KB)"
echo "  - 'Split N bytes into M fragments' (should see 4-5 fragments)"
echo "  - 'queued=N' in GetPacketsToSend (if window fills)"
echo "  - 'TLS handshake complete!' (success)"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Run server with debug logging
exec env VPN_LOG_LEVEL=debug ../build/demos/simple_vpn_server ../configs/server_config_large_certs.json
