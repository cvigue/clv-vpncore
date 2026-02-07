# clv-vpncore

OpenVPN-compatible VPN server and client built with C++23, ASIO coroutines, and a zero-copy data path.

At this point it is all still very new and not well tested, even though it tests as functional on a reasonably new Linux with a reasonably new (clang 21.x or GCC 14.x) compiler.

## Overview

clv-vpncore is a from-scratch OpenVPN implementation providing both a **server** and a **client**. The server is tested against stock OpenVPN 2.6.14 clients; the client connects to the clv-vpncore server (and should interoperate with stock OpenVPN servers). Both support a **userspace data path** (batched `recvmmsg`/`sendmmsg` with an in-place encryption arena) and **DCO kernel offload** via the Linux `ovpn-dco` module.

Key capabilities:

- TLS 1.3 control channel with tls-crypt-v2
- AEAD data channel (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305) with NCP negotiation
- Dual-stack IPv4/IPv6 tunneling with independent pool management, routing, and masquerade
- Multi-client sessions with IP pool management and longest-prefix-match routing
- UDP and TCP transport
- Data Channel Offload (DCO) with kernel keepalive and netlink stats (server and client)
- Zero-copy arena inbound/outbound data path (userspace mode)
- Full client: auto-reconnect with back-off, keepalive timeout detection, .ovpn config parsing
- Periodic stats reporting with throughput, batch depth, and buffer headroom
- Per-subsystem structured logging with config and environment variable overrides
- 580+ unit tests (GoogleTest)

## Dependencies

Built on [clv-base](https://github.com/cvigue/clv-base) (git submodule), which provides:

- **Core** — data structures, concurrency primitives (header-only)
- **SslHelp** — SSL/TLS wrapper library (header-only)
- **NetCore** — networking, STUN, TUN device support
- **External** — ASIO, GoogleTest, spdlog, nghttp3, quictls

## Building

```bash
git clone --recursive git@github.com:cvigue/clv-vpncore.git
cd clv-vpncore
mkdir build && cd build
cmake ..
cmake --build . -j$(nproc)
ctest -j$(nproc)
```

## Project Structure

```
clv-vpncore/
├── clv-base/           Submodule: Core, SslHelp, NetCore, extern (ASIO, quictls, …)
├── src/
│   ├── openvpn/        OpenVPN protocol: control channel, data channel, TLS,
│   │                   session manager, config parser, DCO integration
│   ├── transport/      UDP/TCP transport, recvmmsg/sendmmsg batching, arena
│   ├── vpn_server.{h,cpp}
│   ├── vpn_client.{h,cpp}
│   ├── ip_pool_manager.{h,cpp}
│   ├── routing_table.{h,cpp}
│   ├── log_subsystems.{h,cpp}    Subsystem logger manager
│   ├── scoped_ip_forward.{h,cpp}  RAII IPv4 forwarding guard
│   ├── scoped_ip6_forward.{h,cpp} RAII IPv6 forwarding guard
│   ├── scoped_masquerade.{h,cpp}  RAII nftables IPv4 masquerade
│   ├── scoped_ipv6_masquerade.{h,cpp} RAII nftables IPv6 masquerade
│   └── …
├── tests/              Unit tests (GoogleTest)
├── demos/              Runnable demos: simple_vpn (unified, experimental),
│                       simple_vpn_server, simple_vpn_client, config generator, .ovpn parser
├── configs/            Server and client JSON configs, sample .ovpn profile
├── scripts/            Helper scripts (test_handshake.sh, test_large_certs.sh)
└── test_data/          Test certificates, .ovpn files
```

## Running

```bash
# Server (requires root for TUN device)
sudo ./build/demos/simple_vpn_server configs/server_config.json

# Client (requires root for TUN/DCO device)
sudo ./build/demos/simple_vpn_client configs/client_config.json
# or with an OpenVPN .ovpn profile:
sudo ./build/demos/simple_vpn_client test_data/test_client.ovpn

# Connect with a stock OpenVPN client
sudo openvpn --config test_data/test_client.ovpn

# Or use the automated handshake test
./scripts/test_handshake.sh
```

The client auto-detects the config format by file extension (`.json` vs `.ovpn`). The `.ovpn` loader handles inline `<ca>`, `<cert>`, `<key>`, and `<tls-crypt>` blocks.

### simple_vpn (Experimental)

> **Status: Experimental** — functional and tested across server/client mode
> combinations (userspace and DCO), but not yet hardened for production use.

`simple_vpn` is a unified executable that runs as server, client, or both from
a single config file. It composes the existing `VpnServer` and `VpnClient` on a
shared `io_context`.

```bash
# Client-only via .ovpn profile (most common)
sudo ./build/demos/simple_vpn my_profile.ovpn

# Server, client, or both via JSON config
sudo ./build/demos/simple_vpn config.json
```

**Features:**
- Single binary for all roles — server-only, client-only, or dual server+client(s)
- Direct `.ovpn` profile support (pass as the sole argument for client mode)
- JSON config with `"server"` and/or `"client"` top-level sections
- Flexible role references: inline config, `"$ref"` to external file, or bare string path
- File paths resolved relative to the master config's directory
- Shared `io_context` for dual-role — both roles run on the same event loop
- Graceful shutdown via SIGINT/SIGTERM
- Post-run client statistics (assigned IP, uptime, bytes sent/received)

**JSON config formats:**

```json
// Dual-role via $ref
{
    "server": { "$ref": "server_config.json" },
    "client": { "$ref": "../test_data/test_client.ovpn" }
}

// Server-only with inline config
{
    "server": { ... server fields ... }
}

// Client-only via bare path
{
    "client": "my_profile.ovpn"
}
```

See `demos/README.md` for full configuration details and additional examples.

## Client

The VPN client implements the full OpenVPN connection lifecycle:

**State machine**: `Disconnected` → `Connecting` → `TlsHandshake` → `Authenticating` → `Connected` → (on failure) `Reconnecting` → …

**Reconnection**: On peer death (DCO kernel notification or userspace keepalive timeout), the client tears down the session, waits `reconnect_delay_seconds`, and re-runs the full handshake. The TLS handshake phase has a 30-second deadline — if the server doesn't respond, the attempt fails and the next retry begins. Retries continue up to `max_reconnect_attempts` (0 = unlimited).

**Keepalive**: The client sends PING every `keepalive_interval` seconds. In userspace mode, it also monitors inbound traffic: if no packet arrives within `keepalive_timeout` seconds, the server is considered dead and reconnection begins. In DCO mode, the kernel delivers peer-death notifications via netlink instead.

**Data path modes**: Same as the server — userspace (batched, zero-copy arena) or DCO (kernel offload). Selected via `performance.enable_dco` in the config.

## Configuration Reference

The server reads a JSON config file. Below is a section-by-section reference.

### `server`

| Field | Default | Description |
|-------|---------|-------------|
| `host` | `"0.0.0.0"` | Bind address |
| `port` | `1194` | Listen port |
| `proto` | `"udp"` | Transport protocol (`"udp"` or `"tcp"`) |
| `dev` | `"tun"` | Device type |
| `dev_node` | `"/dev/net/tun"` | TUN device path |
| `keepalive` | `[10, 120]` | `[ping_interval, timeout]` in seconds |

### `crypto`

| Field | Description |
|-------|-------------|
| `ca_cert` | CA certificate path |
| `server_cert` / `server_key` | Server certificate and private key |
| `dh_params` | Diffie-Hellman parameters file |
| `cipher` | Data channel cipher: `"AES-256-GCM"`, `"AES-128-GCM"`, `"CHACHA20-POLY1305"` |
| `auth` | HMAC digest (e.g. `"SHA256"`) |
| `tls_cipher` | Control channel TLS cipher suite |
| `keysize` | Key size in bits |
| `tls_crypt_key` | tls-crypt (v1/v2) pre-shared key path |

### `network`

| Field | Description |
|-------|-------------|
| `server_network` | IPv4 tunnel subnet in CIDR (e.g. `"10.8.0.0/24"`) |
| `server_network_v6` | IPv6 tunnel subnet in CIDR (e.g. `"fd00::/112"`). Empty = IPv6 disabled |
| `server_bridge` | Server-side tunnel IP |
| `client_dns` | DNS servers pushed to clients |
| `routes` | IPv4 subnets routed through the tunnel |
| `routes_v6` | IPv6 subnets routed through the tunnel (pushed as `route-ipv6`) |
| `push_routes` | Push routes to clients on connect |
| `tun_mtu` | TUN device MTU (pushed to clients in PUSH_REPLY) |
| `tun_txqueuelen` | TUN TX queue length (0 = OS default) |

### `auth`

| Field | Description |
|-------|-------------|
| `client_cert_required` | Require client certificates |
| `username_password` | Enable username/password auth |
| `crl_verify` / `crl_file` | Certificate revocation list |

### `performance`

| Field | Default | Description |
|-------|---------|-------------|
| `max_clients` | `100` | Maximum simultaneous clients |
| `enable_dco` | `false` | Use kernel DCO data path instead of userspace |
| `batch_size` | `4096` | recvmmsg/sendmmsg batch depth (clamped to 4096) |
| `process_quanta` | `128` | Packets processed per event-loop chunk before yielding. Prevents HOL blocking on large batches. 0 = no chunking (process entire batch before yielding). |
| `lame_duck_seconds` | `0` | Lame-duck key lifetime after rekey. `0` = no timer (lives until next rekey). |
| `cpu_affinity` | `-1` (off) | Pin reactor thread: `-1`=off, `"auto"`=pin to current core, `"adaptive"`=monitor+probe, `N`=explicit core |
| | | Adaptive sub-keys (object form): `probe_interval`, `probe_duration`, `baseline_windows`, `ema_alpha`, `throughput_threshold` |
| `socket_recv_buffer` | `0` (OS default) | UDP `SO_RCVBUF` size in bytes |
| `socket_send_buffer` | `0` (OS default) | UDP `SO_SNDBUF` size in bytes |
| `stats_interval_seconds` | `0` (disabled) | Periodic stats report interval |
| `ping_timer_remote` | `60` | Remote ping timer (seconds) |
| `renegotiate_seconds` | `3600` | Key renegotiation interval |

See the [tuning appendix](#appendix-batch--buffer-tuning) for guidance on `batch_size` and socket buffer values.

### Client Configuration

The client reads a JSON config file or a standard `.ovpn` profile (auto-detected by extension).

#### `server`

| Field | Default | Description |
|-------|---------|-------------|
| `host` | `""` | Server hostname or IP |
| `port` | `1194` | Server port |
| `proto` | `"udp"` | Transport protocol (`"udp"`) |
| `keepalive` | `[10, 60]` | `[ping_interval, timeout]` in seconds |

#### `crypto`

| Field | Description |
|-------|-------------|
| `ca_cert` | CA certificate path |
| `client_cert` / `client_key` | Client certificate and private key |
| `tls_crypt_key` | tls-crypt pre-shared key path |
| `cipher` | Preferred data channel cipher (server may override via NCP) |
| `auth` | HMAC digest |

#### `reconnect`

| Field | Default | Description |
|-------|---------|-------------|
| `delay_seconds` | `5` | Seconds to wait between reconnect attempts |
| `max_attempts` | `10` | Maximum reconnect attempts (`0` = unlimited) |

#### `performance` (client)

| Field | Default | Description |
|-------|---------|-------------|
| `enable_dco` | `false` | Use kernel DCO data path |
| `socket_recv_buffer` | `0` | UDP `SO_RCVBUF` size in bytes |
| `socket_send_buffer` | `0` | UDP `SO_SNDBUF` size in bytes |
| `batch_size` | `4096` | recvmmsg/sendmmsg batch depth |
| `process_quanta` | `0` | Packets per yield (`0` = no chunking, appropriate for single-peer clients) |
| `cpu_affinity` | `-1` | Pin reactor thread (`-1` = off) |
| `stats_interval_seconds` | `0` | Periodic stats interval (`0` = disabled) |

#### `logging` (client)

| Field | Default | Description |
|-------|---------|-------------|
| `verbosity` | `3` | Log level: 0=off, 1=critical, 2=error, 3=warn, 4=info, 5=debug, 6=trace |

### `logging`

| Field | Description |
|-------|-------------|
| `verbosity` | Default log level — spdlog name (`"trace"`, `"debug"`, `"info"`, `"warn"`, `"err"`, `"critical"`, `"off"`) or numeric (`0`–`6`) |
| `subsystems` | Per-subsystem level overrides (JSON object, keys are subsystem names) |

Subsystem names: `keepalive`, `sessions`, `control`, `dataio`, `routing`, `general`.

Example:
```json
"logging": {
    "verbosity": "info",
    "subsystems": {
        "dataio": "warn",
        "control": "debug"
    }
}
```

Environment variables override config values (highest priority):

```bash
# Override the default level for all subsystems
sudo VPN_LOG_LEVEL=debug ./build/demos/simple_vpn_server configs/server_config.json

# Override a single subsystem (set by SubsystemLoggerManager at startup)
SPDLOG_LEVEL_vpn_dataio=trace  sudo ./build/demos/simple_vpn_server configs/server_config.json
```

Priority order: **env var** > **config `subsystems`** > **config `verbosity`**.

## Stats Reports

When `stats_interval_seconds > 0`, both the server and client log periodic data-path statistics. The format depends on the active mode:

**Userspace mode** (`[stats]`):
```
[stats] 30.0s: rx=4213207 (1600M) tx=734645 (19M) rx[00,00,01,05,93,00,00,00]-0 tx[100,00,00,00,00,00,00,00]-0 buf=42/3568ms dec=4213207/0 rmiss=0 serr=0
```

**DCO mode** (`[stats/dco]`):
```
[stats/dco] 60.0s: rx=95420 pkts (603.1 Mbps) tx=94311 pkts (596.2 Mbps) buf_rx=35ms buf_tx=18ms peers=1
```

| Field | Meaning |
|-------|---------|
| `rx` / `tx` | Packets and throughput in the stats window |
| `batch=[...]` | Per-window recvmmsg batch histogram — 8 linear bins of 512 packets, non-zero only (userspace) |
| `buf_rx` / `buf_tx` | Socket buffer headroom in milliseconds at current throughput |
| `decrypt_ok` / `decrypt_err` | Successful / failed AEAD decryptions |
| `route_miss` | Packets with no matching route entry |
| `send_err` | sendmmsg failures |
| `peers` | Connected peer count (DCO only) |

The `buf_rx` and `buf_tx` values indicate how many milliseconds of traffic the kernel socket buffer can absorb at the current data rate. Low values (< 10 ms) suggest the buffer may overflow during traffic bursts, causing UDP drops and TCP retransmissions.

## Testing

```bash
cd build
ctest -j$(nproc)                                          # all tests
./tests/test_vpncore --gtest_filter="DataChannel*"        # specific suite
```

Coverage includes protocol parsing, TLS handshake, key derivation, AEAD encrypt/decrypt, replay protection, config validation, IP pool management, routing, UDP batching, and session lifecycle.

## Architecture

Single-threaded `asio::io_context` event loop with C++20 coroutines (both server and client). The data channel is a `std::variant<Userspace, DCO>` dispatched via `std::visit` — no virtual functions in the hot path.

**Server**: Multi-client session manager, IP pool allocation, longest-prefix-match routing, and RAII host networking (forwarding, masquerade). Coroutines: `UdpReceiveLoop`, `TunToServerBatch`, `SessionCleanupLoop`, `StatsLoop`, `KeepaliveMonitor`.

**Client**: Connection state machine (`Disconnected` → `Connected`) driven by `ConnectionLoop`. On connect: TLS handshake with retransmit timer, key-method-2 exchange, PUSH_REPLY processing, TUN/DCO device setup, then delegate to the data path strategy. On disconnect: all per-session state is reset (control channel, TLS-crypt, key material, config exchange, pushed config) so reconnection starts from a clean slate. Coroutines: `ConnectionLoop`, `ReconnectLoop`, `UdpReceiveLoop`, `TunToServerBatch`, `KeepaliveLoop`, `StatsLoop`, `DcoKeepaliveMonitor`, `DcoReceiveLoop`.

**Userspace data path**: A pre-allocated arena of `batch_size × 2048` byte slots. `recvmmsg(2)` writes datagrams directly into arena slots; AEAD decrypt operates in-place; plaintext is written to the TUN fd via `writev(2)`. Outbound follows the reverse: `read(tun_fd)` into arena slots, in-place encrypt, `sendmmsg(2)`. Zero heap allocations per packet.

**DCO data path**: The kernel `ovpn-dco` module handles encrypt/decrypt. The server manages sessions and keys via generic netlink, monitors peer health via multicast netlink events, and queries per-peer stats via `OVPN_CMD_GET_PEER`.

**IPv6**: Dual-stack support throughout. The server assigns IPv6 addresses from a configurable pool (`server_network_v6`), adds the address to the TUN/DCO interface, enables IPv6 forwarding and ip6 masquerade via RAII guards, pushes `ifconfig-ipv6` and `route-ipv6` directives to clients, and maintains a separate `RoutingTableIpv6` for data-plane routing. Both userspace and DCO modes register the peer's IPv6 address.

## License

Copyright (c) 2025- Charlie Vigue. All rights reserved.

---

## Appendix: Batch & Buffer Tuning

Findings from iperf3 testing over a real VPN tunnel (AES-256-GCM, AES-NI, virtio NICs capable of 15–22 Gbps, Xeon Gold 6242). Client uses OpenVPN 2.6 with DCO (`openvpn-dco-dkms`).

### Batch size

`batch_size` controls how many datagrams are passed to `recvmmsg(2)` / `sendmmsg(2)` per syscall. Larger batches amortize syscall overhead but increase the time the event loop is blocked per iteration. Defaults to the hard limit, 4096.

### Process quanta

`process_quanta` controls how many packets are processed per event-loop chunk before yielding with `co_await asio::post()`. This prevents head-of-line blocking: without yielding, a large batch holds the reactor for 1–2 ms, starving the TUN-read coroutine and preventing TCP ACKs from being forwarded — causing retransmits on the inner connection. A value of 0 disables chunking entirely (the full batch is processed before yielding), which is appropriate for clients where there is no competing multi-session workload.

| process_quanta | Avg Gbps | Peak Gbps | TCP Retries |
|----------------|----------|-----------|-------------|
| 96             | 2.36     | 2.54      | 0           |
| 128            | 1.79     | 2.31      | 0           |
| 256            | 1.55     | 1.94      | 0           |
| 512            | 1.49     | 1.69      | 1           |

Q=128 gives the most consistent results across runs. Q=96 can reach higher peaks but shows more variance. Default: 128.

### Socket buffers

`socket_recv_buffer` and `socket_send_buffer` set the kernel UDP buffer sizes (`SO_RCVBUF` / `SO_SNDBUF`). The stats report shows effective headroom in milliseconds.

**4 MB recv / 4 MB send** is a good starting point for Gbps-class links; monitor `buf_rx` in the stats output and increase if it drops below ~20 ms.

### Lame duck keys

`lame_duck_seconds` controls how long the previous data-channel key is retained after a rekey. At multi-Gbps rates, in-flight packets encrypted with the old key can arrive well after the new key is installed. Setting `lame_duck_seconds=0` disables the timer entirely — the old key lives until the *next* rekey (WireGuard-style). This eliminates spurious "no key found" decrypt errors during renegotiation.
