# Coverage Analysis

**Date:** 2026-07-11 (regenerated after client-initiated rekey / RK1–RK3 unit coverage)
**Method:** LLVM source-based coverage (`-fprofile-instr-generate -fcoverage-mapping`, Clang 21)
**Build dir:** `build-cov/` (Debug + coverage flags, no ASAN)
**Tests:** 958 passed, 19 skipped (TUN device — require root/`/dev/net/tun`)
**Overall:** 44.18% lines (−1.18pp vs 2026-04-16; codebase grew), 42.66% branches, 55.54% functions across `src/`

Notable since last report: `openvpn/control_channel.cpp` **48.81% → 54.94%** (+6.1pp) after soft-reset success / crossed-reset unit tests (`ControlChannelHandshakeTest`).

---

## Coverage by file

| File | Lines | Missed | % lines | % funcs |
|---|---|---|---|---|
| `client_control_adapter.h` | 859 | 635 | 26.08% | 36.84% |
| `client_data_adapter.h` | 15 | 15 | 0.00% | 0.00% |
| `client_dco_channel.h` | 117 | 110 | 5.98% | 7.14% |
| `client_tcp_channel.h` | 301 | 301 | 0.00% | 0.00% |
| `client_udp_channel.h` | 196 | 172 | 12.24% | 26.67% |
| `cpu_affinity.cpp` | 110 | 25 | 77.27% | **100%** |
| `data_path_stats.h` | 135 | 6 | 95.56% | 94.12% |
| `data_transport.h` | 49 | 27 | 44.90% | 35.71% |
| `dco_client_data_mixin.h` | 136 | 129 | 5.15% | 7.14% |
| `dco_core.cpp` | 399 | 380 | 4.76% | 25.00% |
| `dco_core.h` | 3 | 3 | 0.00% | 0.00% |
| `dco_netlink_ops.h` | 324 | 264 | 18.52% | 16.67% |
| `dco_server_data_mixin.h` | 346 | 346 | 0.00% | 0.00% |
| `dco_utils.h` | 36 | 25 | 30.56% | 50.00% |
| `iface_utils.h` | 162 | 162 | 0.00% | 0.00% |
| `ip_pool_manager.cpp` | 164 | 5 | 96.95% | **100%** |
| `keepalive_loop.h` | 54 | 54 | 0.00% | 0.00% |
| `log_subsystems.cpp` | 88 | 10 | 88.64% | **100%** |
| `log_subsystems.h` | 3 | 0 | **100%** | **100%** |
| `multi_peer_policy.h` | 141 | 141 | 0.00% | 0.00% |
| `nft_subnet_target.cpp` | 49 | 0 | **100%** | **100%** |
| `openvpn/aead_traits.h` | 16 | 0 | **100%** | **100%** |
| `openvpn/aead_utils.h` | 18 | 0 | **100%** | **100%** |
| `openvpn/client_config_generator.cpp` | 188 | 27 | 85.64% | **100%** |
| `openvpn/config_exchange.cpp` | 518 | 51 | 90.15% | 97.73% |
| `openvpn/config_exchange.h` | 17 | 0 | **100%** | **100%** |
| `openvpn/connection.cpp` | 24 | 3 | 87.50% | **100%** |
| `openvpn/connection.h` | 161 | 42 | 73.91% | 71.11% |
| `openvpn/control_channel.cpp` | 577 | 260 | 54.94% | 73.33% |
| `openvpn/control_channel.h` | 64 | 14 | 78.12% | 80.00% |
| `openvpn/control_channel_fragment.h` | 27 | 0 | **100%** | **100%** |
| `openvpn/control_plane_helpers.cpp` | 189 | 189 | 0.00% | 0.00% |
| `openvpn/control_plane_helpers.h` | 29 | 0 | **100%** | **100%** |
| `openvpn/crypto_algorithms.h` | 125 | 17 | 86.40% | **100%** |
| `openvpn/crypto_context.cpp` | 364 | 71 | 80.49% | 75.00% |
| `openvpn/crypto_context.h` | 113 | 3 | 97.35% | **100%** |
| `openvpn/crypto_context_hmac.h` | 35 | 7 | 80.00% | **100%** |
| `openvpn/crypto_context_limits.h` | 69 | 7 | 89.86% | 89.47% |
| `openvpn/crypto_log.cpp` | 7 | 0 | **100%** | **100%** |
| `openvpn/crypto_log.h` | 3 | 0 | **100%** | **100%** |
| `openvpn/data_v2_decrypt.h` | 108 | 17 | 84.26% | **100%** |
| `openvpn/data_v2_encrypt.h` | 29 | 3 | 89.66% | **100%** |
| `openvpn/data_v2_wire.h` | 8 | 0 | **100%** | **100%** |
| `openvpn/dco_data_channel.h` | 13 | 13 | 0.00% | 0.00% |
| `openvpn/key_derivation.cpp` | 189 | 17 | 91.01% | **100%** |
| `openvpn/key_derivation.h` | 3 | 0 | **100%** | **100%** |
| `openvpn/ovpn_config_parser.cpp` | 371 | 33 | 91.11% | 89.80% |
| `openvpn/packet.cpp` | 293 | 20 | 93.17% | **100%** |
| `openvpn/packet.h` | 93 | 18 | 80.65% | 70.00% |
| `openvpn/protocol_constants.h` | 30 | 7 | 76.67% | 50.00% |
| `openvpn/push_exchange_helpers.cpp` | 98 | 79 | 19.39% | 50.00% |
| `openvpn/push_exchange_helpers.h` | 75 | 27 | 64.00% | **100%** |
| `openvpn/session_manager.cpp` | 77 | 0 | **100%** | **100%** |
| `openvpn/session_manager.h` | 14 | 0 | **100%** | **100%** |
| `openvpn/tcp_data_channel.h` | 367 | 367 | 0.00% | 0.00% |
| `openvpn/tls_context.cpp` | 123 | 5 | 95.93% | **100%** |
| `openvpn/tls_context.h` | 10 | 3 | 70.00% | 75.00% |
| `openvpn/tls_crypt.cpp` | 215 | 21 | 90.23% | **100%** |
| `openvpn/tls_crypt.h` | 19 | 0 | **100%** | **100%** |
| `openvpn/tls_crypt_v2.cpp` | 301 | 52 | 82.72% | 95.00% |
| `openvpn/udp_data_channel.h` | 27 | 27 | 0.00% | 0.00% |
| `openvpn/vpn_config.cpp` | 411 | 65 | 84.18% | 92.31% |
| `openvpn/vpn_config.h` | 6 | 0 | **100%** | **100%** |
| `p2p_policy.h` | 97 | 8 | 91.75% | 94.44% |
| `platform/linux/nftables/nftables_client.cpp` | 386 | 385 | 0.26% | 2.50% |
| `platform/linux/nftables/nftables_client.h` | 2 | 1 | 50.00% | 50.00% |
| `platform/linux/tun/tun_device.cpp` | 273 | 245 | 10.26% | 36.84% |
| `platform/linux/tun/tun_device.h` | 18 | 6 | 66.67% | 60.00% |
| `platform/linux/tun/tun_setup.h` | 36 | 36 | 0.00% | 0.00% |
| `route_utils.h` | 216 | 216 | 0.00% | 0.00% |
| `routing_table.h` | 84 | 7 | 91.67% | 85.71% |
| `scoped_nft_rule.h` | 93 | 71 | 23.66% | 44.44% |
| `scoped_proc_toggle.h` | 59 | 59 | 0.00% | 0.00% |
| `server_control_base.h` | 781 | 770 | 1.41% | 2.56% |
| `server_data_adapter.h` | 60 | 60 | 0.00% | 0.00% |
| `server_dco_control_adapter.h` | 63 | 63 | 0.00% | 0.00% |
| `server_tcp_control_adapter.h` | 58 | 58 | 0.00% | 0.00% |
| `server_udp_control_adapter.h` | 81 | 81 | 0.00% | 0.00% |
| `socket_utils.h` | 16 | 13 | 18.75% | **100%** |
| `traffic_policy.h` | 19 | 0 | **100%** | **100%** |
| `transport/batch_constants.h` | 5 | 1 | 80.00% | **100%** |
| `transport/connector.cpp` | 49 | 19 | 61.22% | 50.00% |
| `transport/connector.h` | 16 | 0 | **100%** | **100%** |
| `transport/listener.cpp` | 84 | 70 | 16.67% | 20.00% |
| `transport/listener.h` | 9 | 6 | 33.33% | 33.33% |
| `transport/packet_arena.h` | 30 | 27 | 10.00% | 11.11% |
| `transport/transport.cpp` | 120 | 51 | 57.50% | 68.18% |
| `transport/transport.h` | 33 | 9 | 72.73% | 57.14% |
| `transport/udp_batch.cpp` | 98 | 5 | 94.90% | **100%** |
| `transport_mode.h` | 24 | 0 | **100%** | **100%** |
| `tunnel_zone.cpp` | 86 | 41 | 52.33% | 80.00% |
| `tunnel_zone.h` | 8 | 8 | 0.00% | 0.00% |
| `udp_client_mixin.h` | 62 | 51 | 17.74% | 25.00% |
| `udp_core.h` | 384 | 365 | 4.95% | 21.05% |
| `udp_engine_types.cpp` | 191 | 36 | 81.15% | 86.96% |
| `udp_engine_types.h` | 7 | 0 | **100%** | **100%** |
| `udp_server_mixin.h` | 187 | 187 | 0.00% | 0.00% |
| `udp_worker_thread.cpp` | 46 | 4 | 91.30% | **100%** |
| `udp_worker_thread.h` | 6 | 0 | **100%** | **100%** |
| `vpn_client.cpp` | 155 | 28 | 81.94% | **100%** |
| `vpn_client.h` | 91 | 13 | 85.71% | 86.96% |
| `vpn_server.cpp` | 119 | 119 | 0.00% | 0.00% |
| `vpn_server.h` | 20 | 20 | 0.00% | 0.00% |

---

## Structural dead zones (integration test territory)

These subsystems have 0% or near-0% unit test coverage because they require a live network stack, kernel TUN interface, or full VPN integration setup. Improving them via unit tests is impractical without mocking at the OS boundary.

| File | Missed lines | Notes |
|---|---|---|
| `openvpn/control_plane_helpers.cpp` | 189 | WrapAndSend, UnwrapAndParse, PRF dispatch — need live TLS+transport |
| `server_control_base.h` | 770 | Server packet-dispatch / rekey loops — needs real connections |
| `client_control_adapter.h` | 635 | Client-side dispatch — full session lifecycle (IT-R* covers rekey) |
| `udp_core.h` | 365 | UDP data-path hot loop — needs live UDP sockets |
| `udp_server_mixin.h` | 187 | Server UDP mixin — needs live sessions |
| `multi_peer_policy.h` | 141 | Multi-peer TX/RX hooks — needs session index |
| `openvpn/tcp_data_channel.h` | 367 | TCP data path — 0% |
| `client_tcp_channel.h` | 301 | TCP client channel — 0% |
| `dco_server_data_mixin.h` | 346 | DCO server — kernel dependency |
| `dco_core.cpp` | 380 | DCO device init — kernel/netlink |
| `dco_client_data_mixin.h` | 129 | DCO client — kernel dependency |
| `vpn_server.cpp` + `vpn_server.h` | 139 | VpnServer::Start, Stop, all paths |
| `transport/listener.cpp` | 70 | TCP server listener |
| `iface_utils.h` | 162 | Interface configuration — requires netlink |
| `route_utils.h` | 216 | Route manipulation — requires netlink |
| `server_udp_control_adapter.h` | 81 | Server UDP control adapter |
| `server_tcp_control_adapter.h` | 58 | Server TCP control adapter |
| `server_dco_control_adapter.h` | 63 | Server DCO control adapter |
| `keepalive_loop.h` | 54 | Needs live session keepalive wiring |

---

## Achievable unit-test gaps (prioritised)

### Still open — `openvpn/control_channel.cpp` (260 missed, 54.94%)

**Now covered (was listed dead in 2026-04-16):**
- `HandleSoftReset` success path — key_id advance, TLS re-init as server, `TlsHandshake` transition, ACK
- Crossed soft-reset early-return (`TlsHandshake` → ACK without key_id bump) on `HandleSoftReset` / `RespondToSoftReset` / second `RequestSoftReset`
- `RequestSoftReset(Client)` success path (key_id 0→1, soft-reset packet)
- `PromoteToKeyMaterialReady` + hard-reset pair bootstrap (`EstablishPair`)

**Still missed / hard:**
- Key-id wrap branch (`new_key_id == 0` → 1) on soft reset — needs seven prior renego cycles or a pure helper
- `RespondToSoftReset` **fresh** path from `KeyMaterialReady` (tests only hit crossed/`TlsHandshake` ACK path)
- `InitiateTlsHandshake` success body — `EstablishPair` pumps TLS via `GetTlsContext()` to avoid a known OpenVPN-framed fragment truncation (server flight ~2182 B → ~1275 B through `GroupTlsRecords`); framed pump is a separate bug to fix
- `GenerateExplicitAck` with pending ACKs but no `peer_session_id`
- `PrepareTlsEncryptedData` / `ProcessPostHandshakeAppData` — post-handshake app data
- TLS re-init failure `catch` paths; `HandleHardReset` without `packet_id`
- Retransmit / window / `GetPacketsToSend` edge cases

### Low — diminishing returns or hard to force

**`cpu_affinity.cpp` (25 missed, 77.27%)** — syscall failure paths (`sched_getcpu`, `sysconf`, `sched_setaffinity`).

**`transport/connector.cpp`** — DNS failure / live TCP.

**`scoped_masquerade.cpp`** — needs nftables + root.

### Currently not achievable / low value

**`openvpn/crypto_context.cpp`** — AEAD dispatch `else` branches effectively unreachable; in-place dispatch remnants.

**`data_transport.h`** — passthrough delegations needing full `DataTransport` + network stack.

---

## How to regenerate

```bash
cmake -S . -B build-cov \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++-21 -DCMAKE_C_COMPILER=clang-21 \
  -DENABLE_ASAN=OFF \
  -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_C_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate"
cmake --build build-cov -j$(nproc) --target test_vpncore

cd build-cov
rm -f /tmp/vpncore_cov_*.profraw
LLVM_PROFILE_FILE="/tmp/vpncore_cov_%p.profraw" ./tests/test_vpncore
llvm-profdata-21 merge /tmp/vpncore_cov_*.profraw -o /tmp/vpncore.profdata

llvm-cov-21 report tests/test_vpncore \
  --instr-profile=/tmp/vpncore.profdata \
  --ignore-filename-regex="(extern|clv-base|tests/|/usr/)"

llvm-cov-21 show tests/test_vpncore \
  --instr-profile=/tmp/vpncore.profdata \
  --sources src/openvpn/control_channel.cpp --format=text \
  | awk '/^ *[0-9]+\| +0\|/'
```
