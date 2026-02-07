# VpnCore Demos

## simple_vpn_server

Production-ready OpenVPN server verified with OpenVPN 2.6.14 clients.

### Features

- ✅ Full TLS-Crypt control channel
- ✅ TLS 1.2+ handshake with certificate verification
- ✅ Multi-cipher support (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
- ✅ Multi-client sessions with IP assignment
- ✅ DCO (Data Channel Offload) kernel support
- ✅ IP routing with longest-prefix-match

### Building

```bash
cd build
ninja simple_vpn_server
```

### Running

**Requirements:**
- Root privileges (for TUN device)
- Linux with `/dev/net/tun`

```bash
sudo ./build/demos/simple_vpn_server configs/server_config.json
```
Add VPN_LOG_LEVEL=debug for debug logging. Other levels are available.

### Testing with OpenVPN Client

```bash
# Auto-test script
./scripts/test_handshake.sh

# Manual test
sudo openvpn --config test_data/test_client.ovpn
```

**Expected Result:**
```
Initialization Sequence Completed
Data Channel: cipher 'AES-256-GCM', peer-id: 7766894
```

### Configuration

See `configs/server_config.json`:

```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 1194,
        "proto": "udp",
        "dev": "tun",
        "dev_node": "/dev/net/tun"
    },
    "crypto": {
        "ca_cert": "test_data/certs/ca.crt",
        "server_cert": "test_data/certs/server.crt",
        "server_key": "test_data/certs/server.key",
        "dh_params": "test_data/certs/dh2048.pem",
        "cipher": "CHACHA20-POLY1305",
        "auth": "SHA256",
        "tls_cipher": "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384",
        "keysize": 256,
        "tls_crypt_key": "test_data/certs/tls-crypt.key"
    },
    "network": {
        "server_network": "10.8.0.0/24",
        "server_bridge": "10.8.0.1",
        "client_dns": [
            "8.8.8.8",
            "8.8.4.4"
        ],
        "routes": [
            "192.168.1.0/24"
        ],
        "push_routes": true
    },
    "auth": {
        "client_cert_required": true,
        "username_password": false,
        "crl_verify": true,
        "crl_file": ""
    },
    "performance": {
        "max_clients": 100,
        "enable_dco": true,
        "keepalive": [
            10,
            120
        ],
        "ping_timer_remote": 60,
        "renegotiate_seconds": 3600
    },
    "logging": {
        "verbosity": 3,
        "log_file": ""
    }
}
```

## simple_vpn_client

OpenVPN client implementation.

### Building

```bash
cd build
ninja simple_vpn_client
```

### Running

```bash
sudo ./build/demos/simple_vpn_client client_config.json
```

See `configs/client_config.json` for example configuration.

## simple_vpn (Experimental)

Unified VPN executable that runs as server, client, or both from a single config
file. Composes the existing `VpnServer` and `VpnClient` on a shared I/O context.

> **Status: Experimental** — functional but not yet fully tested across all
> configuration combinations.

### Building

```bash
cd build
ninja simple_vpn
```

### Running

**Client-only via .ovpn profile:**
```bash
sudo ./build/demos/simple_vpn my_profile.ovpn
```

**Server, client, or both via JSON config:**
```bash
sudo ./build/demos/simple_vpn configs/simple_vpn_config.json
```

### Configuration

The JSON config contains optional `"server"` and/or `"client"` top-level
sections. Whichever roles are present will be started. Each section can be:

- **Inline object** — the full role config embedded directly
- **`$ref` object** — `{ "$ref": "path/to/config.json" }` or `{ "$ref": "profile.ovpn" }`
- **Bare string** — `"path/to/config.json"` or `"profile.ovpn"`

File paths are resolved relative to the master config's directory.

**Dual-role (server + client) via `$ref`:**
```json
{
    "server": { "$ref": "server_config.json" },
    "client": { "$ref": "client_config.json" }
}
```

**Server-only with inline config:**
```json
{
    "server": { ... server fields ... }
}
```

**Client-only via .ovpn reference:**
```json
{
    "client": "my_profile.ovpn"
}
```

See `configs/simple_vpn_config.json`, `configs/simple_vpn_server_only.json`, and
`configs/simple_vpn_client_only.json` for working examples.
