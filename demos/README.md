# VpnCore Demos

## simple_vpn

Unified VPN node binary — runs 0‑1 server instances and 0‑N client connections
in a single process on a shared `io_context`.

### Building

```bash
cd build
ninja simple_vpn
```

### Running

**Requirements:**
- Root privileges when a `"server"` section is present (TUN device creation)
- Linux with `/dev/net/tun`

```bash
# Server-only
sudo ./build/demos/simple_vpn configs/server_config.json

# Client-only
sudo ./build/demos/simple_vpn configs/client_config.json

# Server + N clients (mesh node)
sudo ./build/demos/simple_vpn configs/simple_vpn_config.json
```

Add `VPN_LOG_LEVEL=debug` for debug logging.

### Testing with OpenVPN Client

```bash
# Auto-test script
./scripts/test_handshake.sh

# Manual test
sudo openvpn --config test_data/test_client.ovpn
```

### Configuration

The JSON config supports the standard VpnConfig sections (`server`, `process`,
`performance`, `logging`) plus a `"clients"` array for multi-peer nodes.

Each `"clients"` entry can be:

- **Inline object** — client fields directly; inherits root `performance`/`logging`
- **String path** — path to a `.json` or `.ovpn` file (self-contained)

Inline clients can override inherited settings with nested `"performance"` or
`"logging"` objects.

**Server-only** — `configs/server_config.json`:

```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 1194,
        "cipher": "AES-256-GCM",
        "ca_cert": "test_data/certs/ca.crt",
        "cert": "test_data/certs/server.crt",
        "key": "test_data/certs/server.key",
        "dh_params": "test_data/certs/dh2048.pem",
        "network": "10.8.0.0/24"
    },
    "process": { "cpu_affinity": "auto" },
    "performance": { "enable_dco": true, "batch_size": 4096 },
    "logging": { "verbosity": "info" }
}
```

**Server + clients** — `configs/simple_vpn_config.json`:

```json
{
    "server": { "..." : "..." },
    "performance": { "batch_size": 4096 },
    "logging": { "verbosity": "info" },
    "clients": [
        {
            "server_host": "10.0.0.2",
            "cert": "test_data/certs/client.crt",
            "key": "test_data/certs/client.key"
        },
        "configs/client_config.json",
        "test_data/test_client.ovpn"
    ]
}
```
