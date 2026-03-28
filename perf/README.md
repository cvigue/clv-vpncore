# VPN Performance Suite

This suite is intentionally separate from the default unit and integration test paths.
It is designed for explicit, opt-in performance measurements using Linux namespaces,
real tunnel traffic, and optional underlay impairment via tc netem.

## Goals

- Keep correctness tests and noisy performance runs separate
- Provide an explicit CLI workflow without tying performance runs into the normal build graph
- Compare clv and official OpenVPN client behavior against the same clv server
- Collect metrics rather than impose brittle throughput thresholds

## Matrices

### Stage 1 Coverage

Scenario axes:

- Client implementation: `clv`, `ovpn`
- Datapath: `user`, `dco`
- VPN transport: `udp`, plus `tcp` for `clv-user`
- Impairment profile: `clean`, `lat20`, `lat100`
- Tunnel traffic: `tcp`, `udp`

Purpose:

- Keep a fast baseline matrix for routine clv vs OpenVPN comparisons
- Cover clean-path throughput plus non-loss latency sensitivity without the noisier stress cases

### Stage 2 Coverage

Scenario focus:

- Reverse-direction TCP for the Stage 1 TCP-over-UDP cases
- Multi-stream TCP (`-P 4` and `-P 8`) for the Stage 1 TCP-over-UDP cases
- Loss-profile TCP scenarios (`lat100_loss1`), moved out of Stage 1

Purpose:

- Quantify headroom beyond the single-stream forward baseline
- Separate directionality effects from aggregate tunnel capacity
- Keep harsher loss scenarios in an explicit deeper-analysis matrix

Both matrices are defined in [perf/run_vpn_perf.sh](run_vpn_perf.sh).

## Requirements

Required for any actual run:

- Linux network namespaces
- root or `sudo`
- built `simple_vpn` binary
- `iperf3`

Required for impaired profiles:

- `tc` with `netem`

Required for official baseline scenarios:

- `openvpn`

Required for DCO scenarios:

- `ovpn-dco` kernel support
- an OpenVPN build with visible DCO support for `ovpn-dco-*`

Missing prerequisites are recorded as per-scenario `skip` results where possible.

## Running

Run the harness directly:

```bash
bash perf/run_vpn_perf.sh --list
bash perf/run_vpn_perf.sh --build-dir build --scenario clv-user-udp-clean-tcp
bash perf/run_vpn_perf.sh --build-dir build --matrix stage1
bash perf/run_vpn_perf.sh --build-dir build --matrix stage2
bash perf/run_vpn_perf.sh --build-dir build --matrix stage1 --verbose-progress
```

Progress output behavior:

- Default mode is compact: the active scenario progress line is updated in place.
- Use `--verbose-progress` to emit per-step run notes and linefeed scenario banners.

Override defaults:

```bash
IPERF_SECONDS=15 IPERF_UDP_BANDWIDTH=400M bash perf/run_vpn_perf.sh --build-dir build --scenario ovpn-dco-udp-clean-udp
```

## Results

Artifacts are written under the build tree by default:

- `build/perf-results/<timestamp>/summary.tsv`
- `build/perf-results/<timestamp>/summary.json`
- `build/perf-results/<timestamp>/<scenario>/...`
- `build/perf-results/latest`

Each scenario directory contains:

- `metadata.env`
- `transport_state.txt`
- `setup.log`
- `server.log`
- `client.log`
- `iperf_server.log`
- `iperf_client.json`
- `iperf_client.stderr`
- `tcp_socket_state.txt` for TCP scenarios

## Notes

- The suite is not registered in default CTest.
- The suite is not part of the normal CMake build targets.
- The suite is not intended for ordinary CI by default.
- Stage 1 treats handshake success plus non-zero transfer as the main sanity bar.
- Stage 2 is intentionally larger and noisier; use it for headroom analysis rather than quick regression checks.
- Throughput, retransmits, jitter, and loss are recorded as report-first metrics.
