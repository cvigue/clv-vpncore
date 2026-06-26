# Coverage Analysis

**Date:** 2026-04-15 (updated 2026-04-16)
**Method:** LLVM source-based coverage (`-fprofile-instr-generate -fcoverage-mapping`, Clang 21)
**Build dir:** `build-cov/` (Debug + coverage flags, no ASAN)
**Tests:** 807 passed, 19 skipped (TUN device — require root/`/dev/net/tun`)
**Overall:** 45.36% lines (+1.13pp), 44.67% branches, 55.16% functions across `src/`

---

## Coverage by file

| File | Lines | Missed | % lines | % funcs |
|---|---|---|---|---|
| `client_control_adapter.h` | 834 | 614 | 26.38% | 47.73% |
| `client_data_adapter.h` | 15 | 15 | 0% | 0% |
| `client_dco_channel.h` | 13 | 10 | 23.08% | 20% |
| `client_tcp_channel.h` | 156 | 156 | 0% | 0% |
| `client_udp_channel.h` | 23 | 6 | 73.91% | 60% |
| `cpu_affinity.cpp` | 63 | 20 | 68.25% | 100% |
| `data_path_stats.h` | 123 | 0 | **100%** | 100% |
| `data_transport.h` | 51 | 35 | 31.37% | 26.67% |
| `dco_client_data_mixin.h` | 133 | 126 | 5.26% | 7.69% |
| `dco_core.cpp` | 310 | 291 | 6.13% | 25% |
| `dco_netlink_ops.h` | 293 | 233 | 20.48% | 16.67% |
| `dco_server_data_mixin.h` | 315 | 315 | 0% | 0% |
| `dco_utils.h` | 33 | 22 | 33.33% | 100% |
| `iface_utils.h` | 145 | 145 | 0% | 0% |
| `ip_pool_manager.cpp` | 164 | 5 | 96.95% | 100% |
| `log_subsystems.cpp` | 88 | 10 | 88.64% | 100% |
| `multi_peer_policy.h` | 222 | 222 | 0% | 0% |
| `openvpn/aead_utils.h` | 18 | 0 | **100%** | 100% |
| `openvpn/client_config_generator.cpp` | 188 | 27 | 85.64% | 100% |
| `openvpn/config_exchange.cpp` | 370 | 80 | 78.38% | 91.18% |
| `openvpn/connection.cpp` | 24 | 3 | 87.50% | 100% |
| `openvpn/connection.h` | 109 | 15 | 86.24% | 84.38% |
| `openvpn/control_channel.cpp` | 504 | 258 | 48.81% | 67.86% |
| `openvpn/control_channel.h` | 58 | 17 | 70.69% | 72.22% |
| `openvpn/control_channel_fragment.h` | 28 | 0 | **100%** | 100% |
| `openvpn/control_plane_helpers.cpp` | 188 | 188 | 0% | 0% |
| `openvpn/crypto_algorithms.h` | 63 | 4 | 93.65% | 100% |
| `openvpn/data_channel.cpp` | 434 | 77 | 82.26% | 70.59% |
| `openvpn/data_channel.h` | 111 | 3 | **97.30%** | 100% |
| `openvpn/data_channel_hmac.h` | 35 | 7 | 80% | 100% |
| `openvpn/dco_data_channel.h` | 13 | 13 | 0% | 0% |
| `openvpn/key_derivation.cpp` | 214 | 18 | 91.59% | 100% |
| `openvpn/ovpn_config_parser.cpp` | 423 | 99 | 76.60% | 100% |
| `openvpn/packet.cpp` | 293 | 28 | 90.44% | 100% |
| `openvpn/packet.h` | 93 | 18 | 80.65% | 70% |
| `openvpn/session_manager.cpp` | 77 | 0 | **100%** | 100% |
| `openvpn/tcp_data_channel.h` | 364 | 364 | 0% | 0% |
| `openvpn/tls_context.cpp` | 123 | 5 | 95.93% | 100% |
| `openvpn/tls_context.h` | 10 | 3 | 70% | 75% |
| `openvpn/tls_crypt.cpp` | 221 | 21 | 90.50% | 100% |
| `openvpn/tls_crypt_v2.cpp` | 300 | 52 | 82.67% | 95% |
| `openvpn/udp_data_channel.h` | 25 | 25 | 0% | 0% |
| `openvpn/vpn_config.cpp` | 343 | 58 | 83.09% | 90% |
| `p2p_policy.h` | 68 | 1 | 98.53% | 100% |
| `route_utils.h` | 212 | 212 | 0% | 0% |
| `routing_table.h` | 84 | 7 | 91.67% | 85.71% |
| `scoped_masquerade.cpp` | 91 | 71 | 21.98% | 20% |
| `server_control_base.h` | 659 | 640 | 2.88% | 6.06% |
| `server_data_adapter.h` | 46 | 46 | 0% | 0% |
| `server_dco_control_adapter.h` | 62 | 62 | 0% | 0% |
| `server_tcp_control_adapter.h` | 59 | 59 | 0% | 0% |
| `server_udp_control_adapter.h` | 81 | 81 | 0% | 0% |
| `socket_utils.h` | 16 | 13 | 18.75% | 100% |
| `transport/batch_constants.h` | 5 | 0 | **100%** | 100% |
| `transport/connector.cpp` | 40 | 17 | 57.50% | 50% |
| `transport/listener.cpp` | 76 | 76 | 0% | 0% |
| `transport/packet_arena.h` | 30 | 27 | 10% | 11.11% |
| `transport/transport.cpp` | 124 | 55 | 55.65% | 68.18% |
| `transport/transport.h` | 30 | 6 | 80% | 66.67% |
| `transport/udp_batch.cpp` | 98 | 5 | 94.90% | 100% |
| `transport_mode.h` | 24 | 0 | **100%** | 100% |
| `udp_client_mixin.h` | 69 | 51 | 26.09% | 25% |
| `udp_core.h` | 396 | 381 | 3.79% | 11.54% |
| `udp_engine_types.cpp` | 270 | 37 | 86.30% | 92% |
| `udp_server_mixin.h` | 207 | 207 | 0% | 0% |
| `udp_worker_thread.cpp` | 38 | 1 | 97.37% | 100% |
| `vpn_client.cpp` | 141 | 21 | 85.11% | 100% |
| `vpn_client.h` | 91 | 13 | 85.71% | 86.96% |
| `vpn_server.cpp` | 91 | 91 | 0% | 0% |
| `vpn_server.h` | 17 | 17 | 0% | 0% |

---

## Structural dead zones (integration test territory)

These subsystems have 0% or near-0% unit test coverage because they require a live network stack, kernel TUN interface, or full VPN integration setup. Improving them via unit tests is impractical without mocking at the OS boundary.

| File | Lines | Notes |
|---|---|---|
| `openvpn/control_plane_helpers.cpp` | 188 | WrapAndSend, UnwrapAndParse, PRF dispatch — need live TLS+transport |
| `server_control_base.h` | 640 | Server packet-dispatch loop — needs real connections |
| `client_control_adapter.h` | 614 | Client-side dispatch — needs full session lifecycle |
| `udp_core.h` | 381 | UDP data-path hot loop — needs live UDP sockets |
| `udp_server_mixin.h` | 207 | Server UDP mixin — needs live sessions |
| `multi_peer_policy.h` | 222 | Multi-peer TX/RX hooks — needs session index |
| `openvpn/tcp_data_channel.h` | 364 | TCP data path — 0% entirely |
| `dco_server_data_mixin.h` | 315 | DCO server — kernel dependency |
| `dco_core.cpp` | 291 | DCO device init — kernel/netlink |
| `dco_client_data_mixin.h` | 126 | DCO client — kernel dependency |
| `vpn_server.cpp` + `vpn_server.h` | 108 | VpnServer::Start, Stop, all paths |
| `transport/listener.cpp` | 76 | TCP server listener |
| `iface_utils.h` | 145 | Interface configuration — requires netlink |
| `route_utils.h` | 212 | Route manipulation — requires netlink |
| `server_*_adapter.h` files | ~248 | Server adapters |

---

## Achievable unit-test gaps (prioritised)

### Still open

**`openvpn/control_channel.cpp` (258 missed, 48.81%)**

Large dead block — most paths require state machine to advance past `TlsHandshake`:
- Line 73: `StartHardReset` already-in-progress guard
- Lines 118-119: `HandleHardReset` debug log branch (no packet_id)
- Lines 164-211: **`HandleSoftReset` entirely dead** — key renegotiation, new key_id, TLS re-init, state transition
- Lines 249-261: `GenerateExplicitAck` edge cases (empty acks, no peer_session_id)
- Lines 283-305: `InitiateTlsHandshake` — TLS response failure path, empty response
- Lines 313-321: `StartSoftReset` — initiator side
- Lines 344-346: `ProcessIncomingPacket` non-control opcode reject
- Lines 382-427: **`PrepareTlsEncryptedData` entirely dead** — post-handshake app data write
- Lines 433-516: `HandleAck`, retransmit/retry, window exhaustion
- Lines 534-572: `CountUnacknowledgedPackets`, `GetPacketsToSend`
- Lines 576-579: `GetReceivedPlaintext`
- Lines 636-669: `ProcessIncomingData` — handshake complete + key-material-ready transitions
- Lines 674-685: `ProcessPostHandshakeAppData` entirely dead

---

### Low — diminishing returns or hard to force

**`cpu_affinity.cpp` (20 missed, 68.25%)**

All remaining missed lines are syscall failure paths that cannot be triggered without process-level signal injection or mocking:
- `sched_getcpu()` failure (line 34)
- `sysconf(_SC_NPROCESSORS_ONLN)` failure ×2 (lines 43, 71)
- `sched_setaffinity()` failure (lines 58, 81)

**`transport/connector.cpp` (17 missed, 57.50%)**
- Line 35: DNS resolution failure throw — needs mock or broken DNS name
- Lines 74-80: `TcpConnector` constructor and `Connect` — need live TCP

**`scoped_masquerade.cpp` (71 missed, 21.98%)**

Entire constructor body is dead. All paths require `nft_` (nftables) and root to run non-trivially.

### Currently not achievable

**`openvpn/data_channel.cpp` (77 missed, 82.26%)**

- `EncryptAeadDispatch` (file-static): `IsSupportedAead` guard in `EncryptPacket` returns early for all non-AEAD ciphers before reaching the `else` branch; AEAD ciphers always have `encrypt_ctx_` set, taking the `if` branch. Effectively unreachable.
- `EncryptAeadInPlaceDispatch`, `DecryptAeadInPlaceDispatch` (file-static): never called from any code path.
- These are refactor remnants.

**`data_transport.h` (35 missed, 31.37%)**

All missed lines are passthrough delegations (`CreateTunDevice`, `InstallKeys`, `SnapshotStats`, etc.). Coverage requires instantiating `DataTransport<ClientUdpChannel, …>` which depends on the full network stack — too much boilerplate for the coverage gain.

---

## How to regenerate

```bash
cd build-cov
make -j$(nproc) test_vpncore
rm -f /tmp/vpncore_cov_*.profraw
LLVM_PROFILE_FILE="/tmp/vpncore_cov_%p.profraw" ./tests/test_vpncore 2>/dev/null
llvm-profdata-21 merge /tmp/vpncore_cov_*.profraw -o /tmp/vpncore.profdata

# Summary table
llvm-cov-21 report tests/test_vpncore \
  --instr-profile=/tmp/vpncore.profdata \
  --ignore-filename-regex="(extern|clv-base|tests/)"

# Uncovered lines for a specific file
llvm-cov-21 show tests/test_vpncore \
  --instr-profile=/tmp/vpncore.profdata \
  --sources src/path/to/file.cpp --format=text 2>/dev/null \
  | awk '/^ *[0-9]+\| +0\|/'
```
