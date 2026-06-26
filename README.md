# clv-vpncore

OpenVPN-compatible VPN server and client built with C++23, ASIO coroutines, and a zero-copy data path.

## Overview

clv-vpncore is a from-scratch OpenVPN implementation providing both a **server** and a **client**. Interoperability with the reference OpenVPN 2.6.x implementation is validated in both directions: our client against an OpenVPN server and an OpenVPN client against our server. Both sides support a **userspace data path** (batched `recvmmsg`/`sendmmsg` with an in-place encryption arena) and **DCO kernel offload** via the Linux `ovpn-dco` module.

Key capabilities:

- TLS 1.3 control channel with tls-crypt-v2
- UDP data channel abstraction that can select either the DCO data channel or a batched userspace
    data channel transport.
- TCP transport supported

### Benchmark Snapshot

Measured on two virtual machines connected via virtio adapters and a host network bridge. Simulated latency is applied with `tc netem` on the underlay NIC. Each row is a single iperf3 TCP run (20 s) through the VPN tunnel. `ovpn` = OpenVPN 2.6.x; `clv` = this project.

**Column key:**

| Column | Meaning |
|--------|---------|
| `DPSRV` | Server data plane: `dco` = kernel offload via `ovpn-dco`, `user` = userspace |
| `DPCLT` | Client data plane: same |
| `SIMPL` | Server VPN implementation |
| `CIMPL` | Client VPN implementation |
| `XPT` | Underlay transport (`udp` throughout) |
| `LAT` | One-way latency injected by netem (ms) |
| `TRAF` | iperf3 traffic type |
| `DIR` | Traffic direction: `fwd` = client→server, `rev` = server→client |
| `THROUGHPUT` | iperf3 measured throughput |
| `HS` | VPN handshake duration (ms) |
| `RT` | TCP retransmits reported by iperf3 |
| `RTT` | Round-trip time from iperf3 |

```
DPSRV DPCLT SIMPL CIMPL XPT  LAT  TRAF  DIR  THROUGHPUT        HS    RT    RTT
--------------------------------------------------------------------------------
user  user  ovpn  ovpn  udp  0    tcp   fwd  783.3 Mbps        1s    518   2.454ms
user  user  ovpn  ovpn  udp  0    tcp   rev  627.5 Mbps        1s    652   3.866ms
user  user  clv   clv   udp  0    tcp   fwd  2.40 Gbps         1s    827   3.029ms
user  user  clv   clv   udp  0    tcp   rev  2.08 Gbps         1s    629   2.729ms
user  user  ovpn  ovpn  udp  30   tcp   fwd  72.2 Mbps         1s    42    32.429ms
user  user  ovpn  ovpn  udp  30   tcp   rev  48.4 Mbps         1s    61    32.535ms
user  user  clv   clv   udp  30   tcp   fwd  481.1 Mbps        1s    1206  31.430ms
user  user  clv   clv   udp  30   tcp   rev  447.2 Mbps        1s    1110  31.282ms

user  dco   ovpn  ovpn  udp  0    tcp   fwd  550.7 Mbps        1s    434   3.184ms
user  dco   ovpn  ovpn  udp  0    tcp   rev  522.0 Mbps        1s    37    7.819ms
user  dco   clv   clv   udp  0    tcp   fwd  2.53 Gbps         1s    286   8.430ms
user  dco   clv   clv   udp  0    tcp   rev  2.27 Gbps         1s    605   2.310ms
user  dco   ovpn  ovpn  udp  30   tcp   fwd  45.6 Mbps         1s    32    31.233ms
user  dco   ovpn  ovpn  udp  30   tcp   rev  124.7 Mbps        1s    193   32.473ms
user  dco   clv   clv   udp  30   tcp   fwd  736.1 Mbps        1s    0     32.225ms
user  dco   clv   clv   udp  30   tcp   rev  475.9 Mbps        1s    205   31.055ms

dco   user  ovpn  ovpn  udp  0    tcp   fwd  943.4 Mbps        1s    52    4.308ms
dco   user  ovpn  ovpn  udp  0    tcp   rev  816.0 Mbps        1s    820   1.658ms
dco   user  clv   clv   udp  0    tcp   fwd  1.81 Gbps         1s    1164  3.218ms
dco   user  clv   clv   udp  0    tcp   rev  2.51 Gbps         1s    86    6.544ms
dco   user  ovpn  ovpn  udp  30   tcp   fwd  352.2 Mbps        1s    5     30.595ms
dco   user  ovpn  ovpn  udp  30   tcp   rev  44.9 Mbps         1s    66    31.388ms
dco   user  clv   clv   udp  30   tcp   fwd  551.0 Mbps        2s    0     30.844ms
dco   user  clv   clv   udp  30   tcp   rev  723.4 Mbps        1s    0     31.637ms

dco   dco   ovpn  ovpn  udp  0    tcp   fwd  2.15 Gbps         1s    130   3.910ms
dco   dco   ovpn  ovpn  udp  0    tcp   rev  2.75 Gbps         1s    172   2.563ms
dco   dco   clv   clv   udp  0    tcp   fwd  2.10 Gbps         1s    91    4.086ms
dco   dco   clv   clv   udp  0    tcp   rev  2.65 Gbps         1s    191   2.424ms
dco   dco   ovpn  ovpn  udp  30   tcp   fwd  551.3 Mbps        1s    0     30.711ms
dco   dco   ovpn  ovpn  udp  30   tcp   rev  551.2 Mbps        1s    0     30.730ms
dco   dco   clv   clv   udp  30   tcp   fwd  551.0 Mbps        1s    0     30.780ms
dco   dco   clv   clv   udp  30   tcp   rev  634.6 Mbps        1s    849   30.692ms
```

A few things worth noting when reading these results:

- **DCO/DCO is the equaliser.** When both sides use kernel offload (`dco/dco`), the two implementations perform similarly — around 2–2.7 Gbps at 0 ms latency and ~550 Mbps at 30 ms. Once the kernel owns encryption and forwarding, the userspace VPN process above it has little opportunity to differentiate. Both `ovpn` and `clv` reach the same ceiling here.

- **Userspace throughput at zero latency.** The `clv` userspace implementation uses a dedicated RX worker thread with `recvmmsg` mini-batch processing, a dedicated TX drain coroutine, and an in-place encryption arena. This architecture delivers noticeably higher throughput than the reference userspace path in the zero-latency case, particularly for the server-side TX direction (reverse traffic). The tradeoff is added implementation complexity.

- **Userspace throughput under latency.** At 30 ms latency the difference is most visible in the `user/user` case: the reference implementation's single-threaded userspace path is sensitive to TCP congestion-control dynamics under latency, while `clv`'s batched path maintains throughput more predictably. Both perform identically when the data plane is kernel-offloaded.

- **Mixed DCO/userspace.** The `user/dco` and `dco/user` rows isolate one side's contribution. The `clv` server-side userspace path (`user/dco`, fwd) shows the benefit of batched server TX; the `dco/user` reverse direction benefits from batched client-side RX processing.

- **RTT tracks expectation.** Measured RTT closely follows the injected netem delay (0 ms → ~3–8 ms tunnel overhead; 30 ms → ~31 ms), confirming the netem delay propagates faithfully end-to-end through the tunnel regardless of implementation.

- **Retransmits.** The `RT` column reflects TCP congestion-control behaviour inside the tunnel. It is a secondary signal — higher counts can indicate data-path pressure or transient scheduler contention, not necessarily throughput loss.

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
│   ├── data_transport          Templatized data-channel engine (DataTransport<Channel,DataAdapter,ControlAdapter>)
│   ├── multi_peer_policy       QSBR-based multi-peer dispatch for server DataTransport
│   ├── p2p_policy              Double-buffered single-peer policy for client DataTransport
│   ├── udp_core                Shared UDP RX/TX core (recvmmsg RX + TX drain coroutine)
│   ├── keepalive_loop          Generic KeepaliveLoop coroutine (client + server)
│   ├── dco_netlink_ops         DCO netlink request helpers
│   ├── dco_utils               DCO device setup utilities
│   ├── iface_utils             Network interface helpers
│   ├── route_utils             ip-route / ip-rule helpers
│   ├── socket_utils            Socket option helpers
│   └── udp_core / dco_core     Shared RX loop core and DCO device management mixins
├── tests/              2022 unit tests (GoogleTest)
├── integration/        Network-namespace integration tests (IT1–IT18)
│   ├── configs/        Per-test server/client JSON configs
│   └── netns/          Namespace setup/teardown scripts
├── demos/              simple_vpn, config generator, .ovpn parser
├── configs/            Sample server/client JSON configs, .ovpn profile
├── scripts/            Deployment and test helper scripts
└── test_data/          Test certificates and .ovpn files
```

## Architecture

The implementation is centered on a small set of concrete transport
compositions.

### Core Composition

`VpnClient` and `VpnServer` are thin shells that select one concrete
`DataTransport` specialization at construction time from a `std::variant`
(UDP, DCO, or TCP). There is no virtual dispatch in the transport/data-path
boundary.

`DataTransport<DataChannelTpl, DataAdapterT, ControlAdapterT>` is the common
composition point:

- `ControlAdapterT<Self>` owns role-specific protocol state and lifecycle.
- `DataAdapterT<Self>` is the callback shim from data-path threads into the control plane.
- `DataChannelTpl<DataAdapterT<Self>>` is the concrete transport/data-path implementation.

The `DataTransport` constructor builds the control adapter first, asks it for
`ChannelArgs()`, constructs the channel in place, and then installs the data
adapter with `SetAdapter(...)`.

### Ownership Model

- `VpnClient` owns config, logger, running state, and one selected client transport.
- `VpnServer` owns config, loggers, running state, masquerade guards, and one selected server transport.
- `DataTransport` owns the concrete channel object.
- The channel owns transport-specific resources. That includes the userspace TUN device for UDP/TCP paths; DCO paths configure kernel-owned interfaces instead.

### Control Plane

- Client control logic lives in `ClientControlAdapter`.
- Shared server control logic lives in `ServerControlBase`, with transport-specific wrappers for UDP, DCO, and TCP.
- The control plane stays single-threaded on its `asio::io_context`; data-path callbacks are marshalled back to it via `asio::post` or atomics.

On the client side, the control adapter owns the connection state machine,
control/data channel protocol state, TLS handshake, config exchange, keepalive,
and reconnect/rekey loops. On the server side, the control layer owns session
management, routing tables, IP allocation, TLS/TLS-crypt handling, and peer
cleanup.

### Data Plane

- Userspace UDP uses dedicated RX and TX worker threads in `UdpCore`.
- The TX path is a single drain coroutine that reads up to `tx_drain_depth` TUN packets, encrypts them, and sends in `tx_send_batch` windows.
- Server UDP publishes routing/session snapshots to workers through `UdpEngineContext` and QSBR so RX/TX can run without control-plane locks.
- DCO mode delegates packet encryption/decryption to the kernel `ovpn-dco` module while the process still owns session, key, and policy orchestration.
- TCP mode uses a TCP-specific channel that owns its listener/threading model separately from the server control plane.

### Binary Structure

`simple_vpn` is a unified process that can host zero or one server instance and
zero or more client instances from configuration. The asymmetry between client
and server remains intentional: they share composition patterns, but not a
single runtime controller.

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
| `tls_crypt_key` | — | TLS-Crypt v1 pre-shared key path (mutually exclusive with `tls_crypt_v2_key`) |
| `tls_crypt_v2_key` | — | TLS-Crypt-V2 server wrapping key path (mutually exclusive with `tls_crypt_key`) |
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
| `client_to_client` | `false` | Push tunnel subnet route so clients can reach each other through the server |
| `client_dns_search_domains` | `[]` | DNS search domains pushed to clients |
| `tun_mtu` | `1500` | TUN device MTU (pushed to clients in PUSH_REPLY) |
| `tun_txqueuelen` | `0` | TUN TX queue length (0 = OS default) |
| `client_cert_required` | `true` | Require client certificates |
| `username_password` | `false` | Enable username/password auth |
| `crl_verify` | `false` | Check certificate revocation list |
| `crl_file` | — | CRL file path |
| `max_clients` | `100` | Maximum simultaneous clients |
| `ping_timer_remote` | `60` | Remote ping timer (seconds) |
| `renegotiate_seconds` | `3600` | Key renegotiation interval (`0` disables; `1..29` is clamped to `30`) |

### `client`

| Field | Default | Description |
|-------|---------|-------------|
| `server_host` | — | Server hostname or IP |
| `server_port` | `1194` | Server port |
| `proto` | `"udp"` | Transport protocol (`"udp"` or `"tcp"`). `.ovpn` files may also contain `"udp6"`/`"tcp6"`, which are normalised to `"udp"`/`"tcp"` with IPv6-only resolution. JSON config must use `"udp"` or `"tcp"` only. |
| `protocol` | alias of `proto` | Backward-compatible alias accepted by parser |
| `cipher` | `"AES-256-GCM"` | Preferred data channel cipher (server may override via NCP) |
| `auth` | `"SHA256"` | HMAC digest |
| `data_ciphers` | `[]` | Optional NCP allowlist (OpenVPN `data-ciphers`) |
| `allow_deprecated_data_ciphers` | `false` | Allow deprecated ciphers listed in `data_ciphers` |
| `ca_cert` | — | CA certificate path |
| `ca_cert_pem` | — | Inline PEM alternative |
| `tls_crypt_key` | — | TLS-Crypt v1 pre-shared key path (mutually exclusive with `tls_crypt_v2_key`) |
| `tls_crypt_key_pem` | — | Inline PEM alternative for v1 key |
| `tls_crypt_v2_key` | — | TLS-Crypt-V2 client key file path (mutually exclusive with `tls_crypt_key`) |
| `tls_crypt_v2_key_pem` | — | Inline PEM alternative for V2 client key |
| `cert` | — | Client certificate |
| `cert_pem` | — | Inline PEM alternative |
| `key` | — | Client private key |
| `key_pem` | — | Inline PEM alternative |
| `dev_name` | `""` | TUN device name (auto if empty) |
| `reconnect_delay_seconds` | `5` | Seconds between reconnect attempts |
| `max_reconnect_attempts` | `10` | Maximum reconnect attempts (`0` = unlimited) |
| `keepalive` | `[10, 60]` | Optional shorthand for `[keepalive_interval, keepalive_timeout]` |
| `keepalive_interval` | `10` | Send PING every N seconds |
| `keepalive_timeout` | `60` | Declare peer dead after N seconds of silence |
| `renegotiate_seconds` | `3600` | Client key renegotiation interval (`0` disables) |

### `process`

Process-global settings (not inherited by individual connections).

| Field | Default | Description |
|-------|---------|-------------|
| `cpu_affinity` | `-1` (off) | Pin reactor thread: `-1`=off, `"auto"`=pin to current core, `N`=explicit core |
| `transit_routing` | absent (auto) | IP forwarding (`ip_forward`): absent = auto (enabled when a server is present, off for client-only), `true`/`false` = explicit override |

### `performance`

Shared tuning — inherited by clients in the `"clients"` array unless overridden.

| Field | Default | Description |
|-------|---------|-------------|
| `enable_dco` | `true` | Use kernel DCO data path instead of userspace |
| `batch_size` | `0` | recvmmsg/sendmmsg RX batch depth (0 = auto) |
| `tx_drain_depth` | `1024` | Max TUN reads per TX drain cycle |
| `tx_send_batch` | `64` | Max packets per `sendmmsg` call (`0` = `tx_drain_depth`) |
| `tx_small_pkt_flush` | `384` | Early flush trigger when a small packet is seen mid-drain (`0` = disabled) |
| `rx_thread_affinity` | `"auto"` | RX worker thread CPU pin (`"off"`, `"auto"`, or core index) |
| `tx_thread_affinity` | `"auto"` | TX drain worker thread CPU pin (`"off"`, `"auto"`, or core index) |
| `max_recv` | `0` | Arena/ring size for recvmmsg (0 = same as `batch_size`) |
| `rx_process_batch` | `64` | Mini-batch size for two-pass decrypt+write (0 = process all at once) |
| `socket_recv_buffer` | `0` (OS default) | UDP `SO_RCVBUF` size in bytes |
| `socket_send_buffer` | `0` (OS default) | UDP `SO_SNDBUF` size in bytes |
| `stats_interval_seconds` | `0` (disabled) | Periodic stats report interval |

See [perf/README.md](perf/README.md) for guidance on `batch_size` and socket buffer values.

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
[stats] 30.0s: rx=4213207 (1600M) tx=734645 (19M) rx[00,00,01,05,93,00,00,00]-0 tx[100,00,00,00]-0 buf=42/3568ms dec=4213207/0 rmiss=0 serr=0
```

**DCO mode** (`[stats/dco]`):
```
[stats/dco] 60.0s: rx=95420 pkts (603.1 Mbps) tx=94311 pkts (596.2 Mbps) buf_rx=35ms buf_tx=18ms peers=1
```

| Field | Meaning |
|-------|---------|
| `rx` / `tx` | Packets and throughput in the stats window |
| `rx[...]` / `tx[...]` | Per-window recvmmsg/sendmmsg batch histogram — 8 linear bins, non-zero counts shown; `-N` suffix is saturation count (userspace only) |
| `buf=X/Yms` | RX/TX socket buffer headroom in milliseconds (userspace combined field) |
| `buf_rx` / `buf_tx` | RX/TX socket buffer headroom in milliseconds (DCO — reported as separate fields) |
| `dec=N/M` | Successful / failed AEAD decryptions |
| `rmiss=N` | Packets with no matching route entry (server only) |
| `serr=N` | sendmmsg failures |
| `peers` | Connected peer count (DCO only) |

The `buf_rx` and `buf_tx` values indicate how many milliseconds of traffic the kernel socket buffer can absorb at the current data rate. Low values (< 10 ms) suggest the buffer may overflow during traffic bursts, causing UDP drops and TCP retransmissions.

## Testing

```bash
cd build
ctest -j$(nproc)                                          # all unit tests (integration tests run separately)
./tests/test_vpncore --gtest_filter="DataChannel*"        # specific suite
bash ../perf/run_vpn_perf.sh --list                       # list explicit perf scenarios
bash ../perf/run_vpn_perf.sh --build-dir "$PWD" --scenario clv-user-udp-clean-tcp
bash ../perf/run_vpn_perf.sh --build-dir "$PWD" --matrix stage1
bash ../perf/run_vpn_perf.sh --build-dir "$PWD" --matrix stage2
bash ../perf/run_vpn_perf.sh --build-dir "$PWD" --matrix stage1 --verbose-progress
```

**Unit tests** (2022): protocol parsing, TLS handshake, TLS-Crypt v1 and v2 (key loading, wrap/unwrap, WKc extraction, tamper detection, replay protection), key derivation, AEAD encrypt/decrypt, replay protection, config validation, IP pool management (IPv4 + IPv6), routing (IPv4 + IPv6), UDP batching, session lifecycle, config exchange round-trip, TX drain-loop behavior, transport layer, log subsystems, server helper functions.

**Integration tests** (19, require root): full-stack VPN connectivity using Linux network namespaces with real TUN devices, kernel routing, and nftables. Tests IT16–IT18 additionally require the `openvpn` binary (≥ 2.6) to be installed and skip gracefully with exit 77 if it is absent.

| Test | Description |
|------|-------------|
| IT1 | Single client handshake and data path. Verifies TLS-Crypt negotiation, IP assignment, and end-to-end tunnel ping. |
| IT2 | Three clients connect concurrently. Validates session multiplexing, independent IP allocation, and simultaneous data paths. |
| IT3 | Four-node mesh: two servers (A, B), two clients (C, D), with B acting as both server and client of A. Tests multi-role operation, client-to-client routing across servers, and transit forwarding between tunnel subnets. |
| IT4 | DCO (kernel-offloaded) data path with a single client. Validates that the `ovpn-dco` kernel module handles encryption and forwarding end-to-end. Skips gracefully if `ovpn-dco` is unavailable. |
| IT5 | Three clients over DCO. Confirms per-client DCO device naming and concurrent sessions in kernel-offloaded mode. Skips gracefully if `ovpn-dco` is unavailable. |
| IT6 | Masquerade and transit forwarding. A LAN host behind the server can be reached through the tunnel, verifying nftables masquerade and pushed route propagation. |
| IT7 | Client reconnect after abrupt disconnect. Confirms server tears down the stale session, recycles the tunnel IP, and the client re-establishes cleanly. |
| IT8 | Netem smoke test: 100 ms latency + 1% packet loss injected on the underlay. Verifies the tunnel stays up and passes data under impairment. |
| IT19 | IPv6 underlay external-connectivity test. Assigns IPv6 underlay addresses in namespaces, connects a `simple_vpn` client with `proto=udp` to the server's IPv6 address, and verifies end-to-end tunnel ping. |
| IT9 | `client_to_client=false` — route-withholding isolation. Confirms the server does not push the tunnel subnet in `PUSH_REPLY`; clients have no kernel route to peer IPs and cannot reach them. |
| IT10 | `client_to_client=false` — one-sided route injection. A single client self-adds the tunnel subnet route (simulating a misconfigured host); the return path is absent so the ping fails. Detects trivial single-sided bypass attempts. |
| IT11 | `client_to_client=false` — full symmetric route injection. Both clients self-add the tunnel subnet route, replicating what `client_to_client=true` would push. With the return path present, only genuine server-side data-path enforcement prevents the ping from succeeding. |
| IT12 | TLS-Crypt-V2 single-client handshake. Validates the `P_CONTROL_WKC_V1` packet flow, WKc unwrapping, per-session TlsCrypt key derivation, and end-to-end tunnel ping using a per-client wrapped key. |
| IT13 | TLS-Crypt-V2 multi-client (3 clients, distinct per-client keys). Confirms that multiple clients, each using a different tls-crypt-v2 key, can simultaneously connect and communicate through the tunnel. |
| IT14 | Mixed DCO/userspace clients with a DCO server. Validates that a DCO multi-peer server simultaneously handles one userspace client (TUN device) and two DCO clients (`ovpn-clientN` devices). Skips if `ovpn-dco` is unavailable. |
| IT15 | Userspace server with DCO clients. Inverse of IT14: a userspace TUN server handles three concurrent DCO clients. Confirms data flows correctly in both directions. Skips if `ovpn-dco` is unavailable. |
| IT16 | **Interop:** reference `openvpn` server + `simple_vpn` client (tls-crypt v1). Validates NCP cipher negotiation, `PUSH_REPLY` parsing, and the data channel against the upstream implementation. Skips if `openvpn` is not installed. |
| IT17 | **Interop:** `simple_vpn` server + reference `openvpn` client. Exercises server-side robustness to openVPN's richer `IV_PROTO` bitmask and verbose peer-info. Skips if `openvpn` is not installed. |
| IT18 | **Interop:** reference `openvpn` server (tls-crypt-v2) + `simple_vpn` client. Cross-implementation tls-crypt-v2 packet format validation; complements IT12/IT13 which test our own server. Skips if `openvpn` is not installed. |

**Performance suite** (explicit only, not part of default CTest): namespace-based tunnel benchmarking with `iperf3`, optional `tc netem` impairment, `clv` and official OpenVPN client variants, and separate artifact capture under `build/perf-results`. The harness defaults to compact single-line progress; add `--verbose-progress` for step-by-step logs. Run it directly via `perf/run_vpn_perf.sh`. See [perf/README.md](perf/README.md).

## License

Copyright (c) 2025- Charlie Vigue. All rights reserved.

