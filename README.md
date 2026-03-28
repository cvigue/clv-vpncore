# clv-vpncore

OpenVPN-compatible VPN server and client built with C++23, ASIO coroutines, and a zero-copy data path.

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
- 669 unit tests + 8 integration tests (GoogleTest, network-namespace harness)

#### Benchmark Snapshot (2026-03-25)

Server: clv-vpncore DCO mode, AES-256-GCM, Xeon Gold 6242, virtio NICs.
All runs: iperf3 -t 60 single-stream TCP through the VPN tunnel.

| Direction | Client | Mode | Throughput | Retransmits |
|-----------|--------|------|-----------|-------------|
| Forward (client→server) | clv | Userspace | 1.42 Gbps | 2,671 |
| Forward (client→server) | clv | DCO | 1.53 Gbps | 137 |
| Forward (client→server) | OpenVPN 2.6 | DCO | 1.48 Gbps | 187 |
| Forward (client→server) | OpenVPN 2.6 | Userspace | 873 Mbps | 144 |
| Reverse (server→client) | clv | Userspace | 2.84 Gbps | 5 |
| Reverse (server→client) | clv | DCO | 2.61 Gbps | 1,152 |
| Reverse (server→client) | OpenVPN 2.6 | DCO | 2.61 Gbps | 1,287 |
| Reverse (server→client) | OpenVPN 2.6 | Userspace | 992 Mbps | 4,081 |

**Observations:**
- DCO forward numbers nearly identical across clients (1.53 vs 1.48) — validates
  that clv session/control overhead is negligible.
- clv userspace forward is 63% faster than official userspace (batched arena path).
- clv userspace reverse is ~2.9× faster than official (2.84 vs 0.99 Gbps, 5 vs 4081 retransmits).
- Reverse DCO retransmits (~1,150–1,287) appear on both clients — kernel module
  receive-path characteristic, not client-side code.


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
│   ├── openvpn/        OpenVPN protocol implementation
│   ├── transport/      UDP/TCP transport layer
│   ├── vpn_server              Multi-client server orchestration
│   ├── vpn_client              Single-connection client with reconnect
│   ├── ip_pool_manager         Dual-stack IPv4/IPv6 address allocation
│   ├── routing_table           Longest-prefix-match routing (IPv4 + IPv6)
│   ├── log_subsystems          Per-subsystem structured logging
│   ├── scoped_masquerade       RAII nftables masquerade (IPv4 + IPv6)
│   ├── scoped_proc_toggle      RAII sysctl toggle (ip_forward, etc.)
│   ├── cpu_affinity            Core pinning helpers
│   ├── data_path_stats         Throughput/batch/buffer statistics
│   ├── dco_netlink_ops         DCO netlink request helpers
│   ├── dco_utils               DCO device setup utilities
│   ├── iface_utils             Network interface helpers
│   ├── route_utils             ip-route / ip-rule helpers
│   ├── socket_utils            Socket option helpers
│   └── udp_receive_loop        Templated coroutine receive loop
├── tests/              669 unit tests (GoogleTest)
├── integration/        Network-namespace integration tests (IT1–IT8)
│   ├── configs/        Per-test server/client JSON configs
│   └── netns/          Namespace setup/teardown scripts
├── demos/              simple_vpn, config generator, .ovpn parser
├── configs/            Sample server/client JSON configs, .ovpn profile
├── scripts/            Deployment and test helper scripts
└── test_data/          Test certificates and .ovpn files
```

## Architecture

### System Structure

```
simple_vpn (unified binary, role from config)
  ├── VpnServer (optional, 0-1)
  │     ├── ServerListener (variant: UDP | TCP)
  │     ├── SessionManager → Connection* (per-peer state)
  │     ├── DataPathEngine (variant: Userspace | DCO)
  │     ├── IpPoolManager, RoutingTable, masquerade
  │     └── Shared helpers (control_plane_helpers, stats, batch)
  ├── VpnClient (0-N, one per outbound connection)
  │     ├── ClientConnector (variant: UDP | TCP)
  │     ├── ControlChannel, DataChannel (own members)
  │     ├── DataChannelStrategy (variant: Userspace | DCO)
  │     ├── TunDevice (per-client, userspace only)
  │     └── Shared helpers (same free functions as server)
  └── Shared protocol layer (stateless free functions)
        ├── control_plane_helpers (10 functions)
        ├── ComputeStatsRates, FormatBatchHist
        ├── EffectiveBatchSize, BuildKeyMethod2Options
        └── ConfigExchange (typed PUSH_REPLY serialize/parse)
```

A single executable whose role is determined entirely by configuration.
The library layer is composable: embedding `VpnClient` or `VpnServer`
independently in other applications is a first-class use case.

`VpnClient` and `VpnServer` remain separate classes because orchestration is
genuinely asymmetric — multi-peer session management vs single-connection
lifecycle with reconnect — but the shared protocol layer captures the real
common behavior as stateless free functions.

### Design Principles

- **Thread-per-role event loop** — each role (server, client) gets its own `asio::io_context` on a dedicated `std::jthread`; C++20 coroutines run cooperatively within each thread. No mutexes in the data path.
- **No virtual functions in the hot path** — `std::variant` + `std::visit` for transport (`UdpTransport | TcpTransport`) and data channel (`UserspaceDataChannel | DcoDataChannel`). Same pattern for `DataPathEngine` and `DataChannelStrategy`.
- **Value semantics, minimal allocation** — `std::optional` over heap pointers, arena-based packet buffers, RAII for all host-networking side effects.
- **Enforcement-plane architecture** — this process enforces VPN policy (TLS auth, IP assignment, routing) but does not decide it. User management, certificate generation, and policy configuration belong to an external management plane.

### Server

Multi-client session manager, IP pool allocation, longest-prefix-match routing, and RAII host networking (forwarding, masquerade). Coroutines: `UdpReceiveLoop`, `TunToServerBatch`, `SessionCleanupLoop`, `StatsLoop`, `KeepaliveMonitor`.

### Client

Connection state machine (`Disconnected` → `Connecting` → `TlsHandshake` → `Authenticating` → `Connected` → `Reconnecting` → …) driven by `ConnectionLoop`. On connect: TLS handshake with retransmit timer, key-method-2 exchange, PUSH_REPLY processing, TUN/DCO device setup, then delegate to the data path strategy. On disconnect: all per-session state is reset (control channel, TLS-crypt, key material, config exchange, pushed config) so reconnection starts from a clean slate. Coroutines: `ConnectionLoop`, `ReconnectLoop`, `UdpReceiveLoop`, `TunToServerBatch`, `KeepaliveLoop`, `StatsLoop`, `DcoKeepaliveMonitor`, `DcoReceiveLoop`.

Multiple `VpnClient` instances compose naturally — each runs on its own `io_context` and thread, fully self-contained with its own transport, control channel, and TLS state.

### Data Path: Userspace

A pre-allocated arena of `batch_size × 2048` byte slots. `recvmmsg(2)` writes datagrams directly into arena slots; AEAD decrypt operates in-place; plaintext is written to the TUN fd via `writev(2)`. Outbound follows the reverse: `read(tun_fd)` into arena slots, in-place encrypt, `sendmmsg(2)`. Zero heap allocations per packet.

### Data Path: DCO (Kernel Offload)

The kernel `ovpn-dco` module handles encrypt/decrypt. The server uses a single multi-peer device (`ovpn-dco0`) and manages sessions and keys via generic netlink, monitors peer health via multicast netlink events, and queries per-peer stats via `OVPN_CMD_GET_PEER`. Clients use one P2P-mode device per connection (`ovpn-clientN`).

### IPv6

Dual-stack support throughout. The server assigns IPv6 addresses from a configurable pool (`network_v6`), adds the address to the TUN/DCO interface, enables IPv6 forwarding and ip6 masquerade via RAII guards, pushes `ifconfig-ipv6` and `route-ipv6` directives to clients, and maintains a separate `RoutingTableIpv6` for data-plane routing. Both userspace and DCO modes register the peer's IPv6 address.

## Running

`simple_vpn` is a unified VPN node that supports 0‑1 server instances and 0‑N
client connections in a single process, each on a dedicated thread with its own
`io_context`.

```bash
# Server-only (requires root for TUN device)
sudo ./build/demos/simple_vpn configs/server_config.json

# Client-only
sudo ./build/demos/simple_vpn configs/client_config.json

# Server + N clients (mesh node)
sudo ./build/demos/simple_vpn configs/simple_vpn_config.json

# Connect with a stock OpenVPN client
sudo openvpn --config test_data/test_client.ovpn

# Automated handshake test
./scripts/test_handshake.sh
```

The `"clients"` array accepts inline objects (inheriting root `performance`/`logging`)
or string paths to `.json`/`.ovpn` files (self-contained):

```json
{
    "server": { "..." : "..." },
    "performance": { "batch_size": 4096 },
    "logging": { "verbosity": "info" },
    "clients": [
        { "server_host": "10.0.0.2", "cert": "c1.crt", "key": "c1.key" },
        "configs/client_config.json",
        "test_data/test_client.ovpn"
    ]
}
```

See `demos/README.md` for full configuration details.

## Configuration Reference

All roles share a single JSON config shape. Top-level sections are all optional —
include only what you need. The unified `simple_vpn` binary inspects which
sections are present to determine what to start.

### `server`

| Field | Default | Description |
|-------|---------|-------------|
| `host` | `"0.0.0.0"` | Bind address |
| `port` | `1194` | Listen port |
| `proto` | `"udp"` | Transport protocol (`"udp"` or `"tcp"`) |
| `dev` | `"tun"` | Device type |
| `dev_node` | `"/dev/net/tun"` | TUN device path |
| `keepalive` | `[10, 120]` | `[ping_interval, timeout]` in seconds |
| `cipher` | `"AES-256-GCM"` | Data channel cipher (`"AES-256-GCM"`, `"AES-128-GCM"`, `"CHACHA20-POLY1305"`) |
| `auth` | `"SHA256"` | HMAC digest |
| `tls_cipher` | `"TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"` | Control channel TLS cipher suite |
| `keysize` | `256` | Key size in bits |
| `ca_cert` | — | CA certificate path |
| `tls_crypt_key` | — | tls-crypt (v1/v2) pre-shared key path |
| `cert` | — | Server certificate |
| `key` | — | Server private key |
| `dh_params` | — | Diffie-Hellman parameters file |
| `network` | `"10.8.0.0/24"` | IPv4 tunnel subnet in CIDR |
| `network_v6` | `""` | IPv6 tunnel subnet in CIDR (empty = IPv6 disabled) |
| `bridge_ip` | `"10.8.0.1"` | Server-side tunnel IP |
| `client_dns` | `["8.8.8.8","8.8.4.4"]` | DNS servers pushed to clients |
| `routes` | `[]` | IPv4 subnets routed through the tunnel |
| `routes_v6` | `[]` | IPv6 subnets routed through the tunnel |
| `push_routes` | `true` | Push routes to clients on connect |
| `tun_mtu` | `1500` | TUN device MTU (pushed to clients in PUSH_REPLY) |
| `tun_txqueuelen` | `0` | TUN TX queue length (0 = OS default) |
| `client_cert_required` | `true` | Require client certificates |
| `username_password` | `false` | Enable username/password auth |
| `crl_verify` | `false` | Check certificate revocation list |
| `crl_file` | — | CRL file path |
| `max_clients` | `100` | Maximum simultaneous clients |
| `ping_timer_remote` | `60` | Remote ping timer (seconds) |
| `renegotiate_seconds` | `3600` | Key renegotiation interval |
| `lame_duck_seconds` | `0` | Lame-duck key lifetime after rekey (`0` = no timer) |

### `client`

| Field | Default | Description |
|-------|---------|-------------|
| `server_host` | — | Server hostname or IP |
| `server_port` | `1194` | Server port |
| `protocol` | `"udp"` | Transport protocol (`"udp"`, `"udp6"`, `"tcp"`) |
| `cipher` | `"AES-256-GCM"` | Preferred data channel cipher (server may override via NCP) |
| `auth` | `"SHA256"` | HMAC digest |
| `ca_cert` | — | CA certificate path |
| `ca_cert_pem` | — | Inline PEM alternative |
| `tls_crypt_key` | — | tls-crypt pre-shared key path |
| `tls_crypt_key_pem` | — | Inline PEM alternative |
| `cert` | — | Client certificate |
| `cert_pem` | — | Inline PEM alternative |
| `key` | — | Client private key |
| `key_pem` | — | Inline PEM alternative |
| `dev_name` | `""` | TUN device name (auto if empty) |
| `reconnect_delay_seconds` | `5` | Seconds between reconnect attempts |
| `max_reconnect_attempts` | `10` | Maximum reconnect attempts (`0` = unlimited) |
| `keepalive_interval` | `10` | Send PING every N seconds |
| `keepalive_timeout` | `60` | Declare peer dead after N seconds of silence |

### `process`

Process-global settings (not inherited by individual connections).

| Field | Default | Description |
|-------|---------|-------------|
| `cpu_affinity` | `-1` (off) | Pin reactor thread: `-1`=off, `"auto"`=pin to current core, `N`=explicit core |

### `performance`

Shared tuning — inherited by clients in the `"clients"` array unless overridden.

| Field | Default | Description |
|-------|---------|-------------|
| `enable_dco` | `true` | Use kernel DCO data path instead of userspace |
| `batch_size` | `0` | recvmmsg/sendmmsg batch depth (clamped to 4096) |
| `process_quanta` | `0` | Packets per event-loop chunk before yielding (`0` = no chunking) |
| `socket_recv_buffer` | `0` (OS default) | UDP `SO_RCVBUF` size in bytes |
| `socket_send_buffer` | `0` (OS default) | UDP `SO_SNDBUF` size in bytes |
| `stats_interval_seconds` | `0` (disabled) | Periodic stats report interval |

See the [tuning appendix](#appendix-batch--buffer-tuning) for guidance on `batch_size` and socket buffer values.

### `logging`

| Field | Default | Description |
|-------|---------|-------------|
| `verbosity` | `"info"` | Default log level — spdlog name (`"trace"`, `"debug"`, `"info"`, `"warn"`, `"err"`, `"critical"`, `"off"`) or numeric (`0`–`6`) |
| `subsystems` | `{}` | Per-subsystem level overrides (JSON object, keys are subsystem names) |

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
sudo VPN_LOG_LEVEL=debug ./build/demos/simple_vpn configs/server_config.json

# Override a single subsystem (set by SubsystemLoggerManager at startup)
SPDLOG_LEVEL_vpn_dataio=trace  sudo ./build/demos/simple_vpn configs/server_config.json
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
ctest -j$(nproc)                                          # default unit + registered tests
ctest --exclude-regex "IT[123]"                            # unit tests only
./tests/test_vpncore --gtest_filter="DataChannel*"        # specific suite
bash ../perf/run_vpn_perf.sh --list                       # list explicit perf scenarios
bash ../perf/run_vpn_perf.sh --build-dir "$PWD" --scenario clv-user-udp-clean-tcp
bash ../perf/run_vpn_perf.sh --build-dir "$PWD" --matrix stage2
```

**Unit tests** (669): protocol parsing, TLS handshake, TLS-Crypt (key loading, wrap/unwrap, tamper detection, replay protection), key derivation, AEAD encrypt/decrypt, replay protection, config validation, IP pool management (IPv4 + IPv6), routing (IPv4 + IPv6), UDP batching, session lifecycle, and config exchange round-trip.

**Integration tests** (8, require root): full-stack VPN connectivity using Linux network namespaces with real TUN devices, kernel routing, and nftables. IT1 — single client handshake and data path. IT2 — multi-client concurrent sessions. IT3 — 4-node mesh topology with client-to-client routing. IT4 — DCO kernel-offloaded data path. IT5 — multi-client DCO. IT6 — masquerade and transit forwarding with route push. IT7 — client reconnect after crash with server session cleanup and IP recycling. IT8 — netem latency and loss smoke test. All include negative validation (traffic blocked after teardown). IT4/IT5 skip gracefully without ovpn-dco; IT8 skips without tc netem.

**Performance suite** (explicit only, not part of default CTest): namespace-based tunnel benchmarking with `iperf3`, optional `tc netem` impairment, `clv` and official OpenVPN client variants, and separate artifact capture under `build/perf-results`. Run it directly via `perf/run_vpn_perf.sh`. See [perf/README.md](perf/README.md).

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
