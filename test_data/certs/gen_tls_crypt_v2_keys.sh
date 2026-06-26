#!/bin/bash
# gen_tls_crypt_v2_keys.sh — Generate tls-crypt-v2 test key materials
#
# Creates a server wrapping key and two client keys (for multi-client tests).
# Requires: openvpn (>= 2.5) accessible on PATH.
#
# Output files (in same directory as script):
#   tls-crypt-v2-server.key   — Server wrapping key (Ks)
#   tls-crypt-v2-client0.key  — Client 0 key (Kc + WKc)
#   tls-crypt-v2-client1.key  — Client 1 key (Kc + WKc)
#   tls-crypt-v2-client2.key  — Client 2 key (Kc + WKc)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

if ! command -v openvpn &>/dev/null; then
    echo "Error: openvpn not found on PATH. Install openvpn >= 2.5."
    exit 1
fi

echo "Generating tls-crypt-v2 server key..."
openvpn --genkey tls-crypt-v2-server tls-crypt-v2-server.key

for i in 0 1 2; do
    echo "Generating tls-crypt-v2 client key ${i}..."
    openvpn --genkey tls-crypt-v2-client tls-crypt-v2-client${i}.key \
        --tls-crypt-v2 tls-crypt-v2-server.key
done

echo ""
echo "Generated:"
ls -la tls-crypt-v2-*.key
