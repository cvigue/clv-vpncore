# Integration Tests

Full-stack VPN connectivity tests using Linux network namespaces. Each test
creates isolated virtual network environments with real TUN devices, kernel
routing, and nftables — no mocking, no stubs.

**Requirements:** root / `CAP_NET_ADMIN`, `simple_vpn` built at
`build/demos/simple_vpn`. Tests IT16–IT18 additionally require the `openvpn`
binary (≥ 2.6) to be installed; they skip gracefully (exit 77) if it is absent.

## Running

```bash
# Run all integration tests
sudo ./integration/run_integration.sh

# Run a single test directly (sets up and tears down its own namespaces)
sudo ./integration/ctest_it16.sh
```

Each `ctest_itN.sh` script calls `netns/setup_vpn.sh`, runs the corresponding
`test_itN_*.sh`, and then calls `netns/teardown_vpn.sh` — so any script can be
invoked standalone without manual namespace management.

Logs are written to `/tmp/vpn-itN/` for each test.

## Test Suite

### self-to-self tests (IT1–IT15, IT19)

All parties are `simple_vpn` instances.

| Test | Topology | Description |
|------|----------|-------------|
| IT1  | 1 server + 1 client | Single client handshake. Verifies TLS-Crypt negotiation, IP assignment, and end-to-end tunnel ping. |
| IT2  | 1 server + 3 clients | Three clients connect concurrently. Validates session multiplexing and simultaneous data paths. |
| IT3  | mesh (4 nodes) | Two servers (A, B) and two clients (C, D) with B acting as server and client of A. Tests multi-role operation and transit forwarding between tunnel subnets. |
| IT4  | 1 server + 1 client (DCO) | DCO (kernel-offloaded) data path. Skips if `ovpn-dco` is unavailable. |
| IT5  | 1 server + 3 clients (DCO) | Three clients over DCO. Skips if `ovpn-dco` is unavailable. |
| IT6  | 1 server + 1 client | Masquerade and transit forwarding. A LAN host behind the server is reached through the tunnel. |
| IT7  | 1 server + 1 client | Client reconnect after abrupt disconnect. Server tears down the stale session and recycles the IP. |
| IT8  | 1 server + 1 client (TCP) | TCP transport handshake and data path. |
| IT19 | 1 server + 1 client (IPv6 underlay) | Underlay IPv6 external connectivity. Client connects with `proto=udp` to an IPv6 server address (`fd99::1`), verifying that the resolver picks an IPv6 endpoint and the tunnel data-path ping succeeds. |
| IT9  | 1 server + 2 clients | `client_to_client=false` — route-withholding isolation. Clients have no route to peer IPs and cannot reach them. |
| IT10 | 1 server + 2 clients | `client_to_client=false` — one-sided route injection. Confirms a single return-path absence blocks the ping. |
| IT11 | 1 server + 2 clients | `client_to_client=false` — full symmetric route injection (expected failure). Both clients self-add the tunnel subnet; tests whether server-side enforcement stops traffic. |
| IT12 | 1 server + 1 client (V2) | TLS-Crypt-V2 single-client handshake. Validates `P_CONTROL_WKC_V1` packet flow, WKc unwrapping, and per-session key derivation. |
| IT13 | 1 server + 3 clients (V2) | TLS-Crypt-V2 multi-client with three distinct per-client wrapped keys. |
| IT14 | DCO server + 3 mixed clients | DCO server handles one userspace client (TUN) and two DCO clients simultaneously. Skips if `ovpn-dco` is unavailable. |
| IT15 | Userspace server + 3 DCO clients | Inverse of IT14. Skips if `ovpn-dco` is unavailable. |

### interop tests (IT16–IT18)

These tests require the reference `openvpn` binary (≥ 2.6) installed at a
standard `PATH` location (e.g. `/usr/sbin/openvpn`).  They skip gracefully on
machines where it is absent.

| Test | Topology | Description |
|------|----------|-------------|
| IT16 | `openvpn` server + `simple_vpn` client | tls-crypt v1. Validates NCP cipher negotiation, `PUSH_REPLY` parsing, and data channel connectivity against the upstream implementation. |
| IT17 | `simple_vpn` server + `openvpn` client | Our server receives a connection from `openvpn`. Exercises server-side robustness to openvpn's richer `IV_PROTO` bitmask and verbose peer-info. |
| IT18 | `openvpn` server + `simple_vpn` client | tls-crypt-v2. Cross-implementation packet format validation. Complements IT12/IT13 which test our own server. |

## Namespace Topology

```
             10.99.0.1                10.99.0.N+1
ns-vpn-server ──────── veth pair ──────── ns-vpn-client-N
    tun0 (10.8.0.1)              (tun0 / ovpn-clientN assigned by VPN)
```

`setup_vpn.sh <N>` creates one server namespace and N client namespaces
connected via veth pairs through a root-namespace bridge.
`teardown_vpn.sh <N>` removes them.

For mesh tests, `setup_mesh.sh` / `teardown_mesh.sh` create four namespaces
(ns-mesh-{a,b,c,d}) in a star topology.

## Configs

`configs/` holds JSON config files for each test role:

| File | Used by |
|------|---------|
| `it_server.json` | IT1, IT2, IT6, IT7, IT8, IT9, IT10, IT11, IT17 (simple_vpn server) |
| `it_client.json` | IT1, IT7, IT8, IT16 (simple_vpn client) |
| `it_server_v2.json` | IT12, IT13 (tls-crypt-v2 server) |
| `it_client_v2.json` | IT12, IT18 (tls-crypt-v2 client) |
| `it_server_dco.json` | IT4, IT5, IT14 (DCO server) |
| `it_client_dco.json` | IT4, IT5 (DCO client) |
| `openvpn/it16_server.conf` | IT16 (`openvpn` server, tls-crypt v1) |
| `openvpn/it17_client.conf` | IT17 (`openvpn` client) |
| `openvpn/it18_server.conf` | IT18 (`openvpn` server, tls-crypt-v2) |

## Certificates

All tests share the key material in `test_data/certs/`:

- `ca.crt` / `ca.key` — test CA
- `server.crt` / `server.key` — server certificate
- `client.crt` / `client.key` — client certificate
- `tls-crypt.key` — shared tls-crypt v1 key
- `tls-crypt-v2-server.key` — tls-crypt-v2 server wrapping key
- `tls-crypt-v2-client{0,1,2}.key` — per-client wrapped keys

Regenerate tls-crypt-v2 keys with:
```bash
bash test_data/certs/gen_tls_crypt_v2_keys.sh
```
