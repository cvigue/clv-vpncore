# VpnCore Test Data

This directory contains test certificates and keys for VpnCore unit testing and development.

## Contents

### `certs/` Directory
- `ca.crt` / `ca.key` - Test Certificate Authority (RSA-2048)
- `server.crt` / `server.key` - Test server certificate (RSA-2048)
- `client.crt` / `client.key` - Test client certificate (RSA-2048)
- `server_small.crt` / `server_small.key` - Compact server certificate (EC P-256)
- `ca_large.crt` / `ca_large.key` - Large CA for fragmentation testing (RSA-4096)
- `server_large.crt` / `server_large.key` - Large server certificate (RSA-4096)
- `client_large.crt` / `client_large.key` - Large client certificate (RSA-4096)
- `dh.pem` - Diffie-Hellman parameters (1024-bit for testing)
- `tls-crypt.key` - OpenVPN tls-crypt static key

## Regenerating Certificates

Run from the `VpnCore/test_data/certs` directory:

```bash
# CA
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/CN=Test CA/O=CLVLib Test/C=US"

# Server cert
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/CN=Test Server/O=CLVLib Test/C=US"
openssl x509 -req -days 3650 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt
rm server.csr

# Client cert
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
    -subj "/CN=Test Client/O=CLVLib Test/C=US"
openssl x509 -req -days 3650 -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt
rm client.csr

# DH params (use 2048 for production)
openssl dhparam -out dh.pem 1024

# tls-crypt key
echo '#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----' > tls-crypt.key
openssl rand -hex 256 | fold -w32 >> tls-crypt.key
echo '-----END OpenVPN Static key V1-----' >> tls-crypt.key
```

### Large Certificate Testing

To generate 4096-bit RSA certificates for testing fragmentation and windowing:

```bash
cd certs/
./gen_large_certs.sh
```

This creates `ca_large.crt`, `server_large.crt`, `client_large.crt` with 4096-bit keys.

**To test:**
```bash
# Server (in one terminal, run from project root):
sudo ./build/demos/simple_vpn configs/server_config_large_certs.json

# Client (in another terminal, run from project root):
sudo ./build/demos/simple_vpn configs/client_config_large_certs.json
```

**Expected observations:**
- TLS Certificate message will be ~5-6KB (4-5 packets at 1250-byte MTU)
- Logs will show `"queued=N"` when fragments exceed window size
- Watch for `"Split N bytes into M fragments"` messages
- Handshake should complete without retransmissions (on loopback)
- With network latency, may see 1 RTT stall when window fills


## Security Note

⚠️ **These certificates are for testing only.** Never use them in production.
