#!/bin/bash
# Generate 4096-bit RSA certificates for large certificate testing
# This tests fragmentation and windowing with certificates that span 6+ packets

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "Generating 4096-bit RSA certificates for large cert testing..."

# CA with 4096-bit key
echo "1. Generating CA (4096-bit)..."
openssl genrsa -out ca_large.key 4096 2>/dev/null
openssl req -new -x509 -days 3650 -key ca_large.key -out ca_large.crt \
    -subj "/CN=Test CA Large/O=CLVLib Test/C=US" 2>/dev/null

# Server cert with 4096-bit key
echo "2. Generating server certificate (4096-bit)..."
openssl genrsa -out server_large.key 4096 2>/dev/null
openssl req -new -key server_large.key -out server_large.csr \
    -subj "/CN=Test Server Large/O=CLVLib Test/C=US" 2>/dev/null
openssl x509 -req -days 3650 -in server_large.csr -CA ca_large.crt -CAkey ca_large.key \
    -CAcreateserial -out server_large.crt 2>/dev/null
rm -f server_large.csr

# Client cert with 4096-bit key
echo "3. Generating client certificate (4096-bit)..."
openssl genrsa -out client_large.key 4096 2>/dev/null
openssl req -new -key client_large.key -out client_large.csr \
    -subj "/CN=Test Client Large/O=CLVLib Test/C=US" 2>/dev/null
openssl x509 -req -days 3650 -in client_large.csr -CA ca_large.crt -CAkey ca_large.key \
    -CAcreateserial -out client_large.crt 2>/dev/null
rm -f client_large.csr

echo ""
echo "Done! Certificate sizes:"
echo "  CA:     $(wc -c < ca_large.crt) bytes"
echo "  Server: $(wc -c < server_large.crt) bytes"
echo "  Client: $(wc -c < client_large.crt) bytes"
echo ""
echo "Expected behavior with 1250-byte MTU:"
echo "  - TLS Certificate message ~5-6KB"
echo "  - Will fragment into 4-5 control packets"
echo "  - Window=4 means 5th packet queues until packet 1 ACKed"
echo "  - Watch logs for 'queued=' and retransmission counts"
