# VPN Performance Suite

Measures VPN throughput between two real VMs over a dedicated data network.
The dev VM runs the clv server; a remote test VM runs the client and iperf3.
All orchestration (SSH, deploy, launch, collect) is handled automatically.

## Architecture

```
  Dev VM (server)                          Test VM (client)
  ┌─────────────────┐    data bridge     ┌─────────────────┐
  │ simple_vpn       │◄──192.168.50.x──►│ simple_vpn       │
  │ iperf3 -s        │    (enp6s19)       │ iperf3 -c        │
  │                   │                    │ (or openvpn)      │
  └─────────────────┘                    └─────────────────┘
         ▲  SSH (management VLAN)                ▲
         └────────── 10.10.1.x ──────────────────┘
```

- **Data network** (`192.168.50.0/24`): isolated Proxmox virtual bridge for VPN
  underlay and iperf3 traffic. No other hosts share this segment.
- **Management network** (`10.10.1.0/24`): VLAN used for SSH orchestration.
  The harness SSHs to the test VM to deploy binaries, start/stop processes,
  and collect logs.

## Axis Model

The harness now expands runs using a Cartesian product of explicit axes.

Default expansion is 8 runs:

`impl(clv,ovpn) × dpsrv(user,dco) × dpclt(user,dco) × transport(udp) × lat(0) × loss(0) × traffic(tcp) × strms(1) × dir(fwd) × tx-partsz(def) × tx-workers(def)`

Legacy `--matrix`, `--scenario`, and `--smode` options are no longer supported.

## Requirements

**Dev VM (local, runs as root via sudo):**

- Built `simple_vpn` binary (`build/demos/simple_vpn`)
- `iperf3`, `jq`
- `tc` with `netem` (for non-zero `--lat` / `--loss` runs)
- `ovpn-dco` kernel module (for DCO server scenarios)
- Root or passwordless `sudo`

**Test VM (remote):**

- Passwordless SSH from the dev VM (via `~/.ssh/config`)
- Passwordless `sudo` on the test VM
- `iperf3`, `rsync`
- `openvpn` in `/usr/sbin/` (for ovpn baseline scenarios)
- `ovpn-dco` kernel module (for DCO client scenarios)

Missing prerequisites are recorded as per-scenario `skip` results.

## Running

```bash
# List current axis values and expanded run count
./perf/run_vpn_perf.sh --list

# Run default axis set (8 runs)
./perf/run_vpn_perf.sh --client-host vpn-test-0

# Narrow to a datapath slice
./perf/run_vpn_perf.sh --client-host vpn-test-0 --dpclt dco --dpsrv user

# Reverse TCP with tuning overrides
./perf/run_vpn_perf.sh --client-host vpn-test-0 --dpclt dco -t 30 --dir rev --dpsrv user --tx-partsz 64 --tx-workers 0

# Multi-axis sweep
./perf/run_vpn_perf.sh --client-host vpn-test-0 --impl clv,ovpn --dpclt user,dco --dpsrv user,dco --lat 0,20 --traffic tcp --strms 1,8 --dir bi

# Arbitrary latency/loss values, including fractional loss
./perf/run_vpn_perf.sh --client-host vpn-test-0 --dpclt user --dpsrv dco --lat 25 --loss 0.05 --traffic tcp

# Verbose per-step progress
./perf/run_vpn_perf.sh --client-host vpn-test-0 --verbose-progress
```

`--client-host` is required for all runs. The host must be reachable via SSH
using the invoking user's `~/.ssh/config` (the harness re-execs under `sudo`
but runs SSH as the original user).

Environment overrides:

```bash
IPERF_SECONDS=15 IPERF_UDP_BANDWIDTH=400M \
   ./perf/run_vpn_perf.sh --client-host vpn-test-0 --impl ovpn --dpclt dco --dpsrv dco --traffic udp
```

Axis flags:

- `--impl clv,ovpn`
- `--dpsrv user,dco`
- `--dpclt user,dco`
- `--transport udp`
- `--lat 0,20,25,100`
- `--loss 0,0.05,1,2`
- `--traffic tcp,udp`
- `--strms 1,4,8`
- `--dir fwd,rev,bi`
- `--tx-partsz def,64,128`
- `--tx-workers def,0,1,2`

Latency and loss are raw numeric axes now, not named scenario profiles.
Any `tc netem`-accepted values can be used, including fractional loss values
such as `--loss 0.05`.

Progress output:

- Default: compact in-place progress line.
- `--verbose-progress`: per-step notes with line breaks.

Note on `--dir`: fwd means client --> server

## Results

Artifacts under the build tree:

```
build/perf-results/<timestamp>/summary.tsv
build/perf-results/<timestamp>/summary.json
build/perf-results/<timestamp>/<NN>_<scenario>[-lat<LAT>-loss<LOSS>]/
    metadata.env
    server.log
    client.log
    iperf_server.log
    iperf_client.json
```

`summary.tsv` / `summary.json` store raw `lat_ms` and `loss_pct` fields.

Terminal summary format:

```text
DPSRV DPCLT IMPL XPT  LAT  LOSS  TRAF DIR STRMS P    W    THROUGHPUT    HS   RT   NOTES
-------------------------------------------------------------------------------------------
user  dco   clv  udp  0    0     tcp  rev 1     64   0    1.58 Gbps     1s   0
user  dco   clv  udp  0    0     tcp  rev 1     64   0    1.73 Gbps     1s   43
user  dco   ovpn udp  0    0     tcp  rev 1     64   0    n/a           -    -    [FAIL] handshake timeout
user  dco   ovpn udp  0    0     tcp  rev 1     64   0    n/a           -    -    [SKIP] ovpn-dco module unavailable
```

Notes:

- There is no standalone `ST` column in terminal output.
- TCP retransmissions are shown in `RT`.
- Failed and skipped runs are indicated in `NOTES` using `[FAIL]` and `[SKIP]` prefixes.
- Full machine-readable status remains in `summary.tsv` and `summary.json`.

## How It Works

1. **Pre-flight** — validates SSH, sudo, iperf3, rsync on the test VM;
   pings the data network to confirm L2 reachability.
2. **Deploy** — rsyncs `simple_vpn`, certs, and configs to `/tmp/clv-perf/`
   on the test VM.
3. **Per scenario:**
   - Clears stale local `simple_vpn`, `iperf3`, TUN, DCO, and netem state.
   - Applies `tc netem` on the local data NIC when `--lat` or `--loss` is non-zero.
   - Starts `simple_vpn` server locally.
   - Starts the client (clv or openvpn) on the test VM via SSH.
   - Waits for handshake (watches server log, falls back to client log).
   - Probes tunnel route with ping.
   - Runs iperf3 through the tunnel.
   - Collects results and logs.
4. **Cleanup** — kills processes, removes tunnel devices, restores the
   data-plane subnet route on the test VM.

## Notes

- The suite is not registered in CTest or the CMake build graph.
- Not intended for ordinary CI — requires two-VM infrastructure.
- Handshake success plus non-zero transfer is the sanity bar.
- Throughput, retransmits, jitter, and loss are recorded as report-first metrics;
  no brittle thresholds are enforced.
