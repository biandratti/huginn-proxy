# eBPF TCP SYN Fingerprinting - Setup Guide

TCP SYN fingerprinting is implemented via an eBPF program (XDP or TC) that captures TCP SYN
packets and stores them in BPF LRU hash maps. The proxy looks up each connection's SYN data
and injects the `x-tcp-p0f` header with the p0f-style signature.

---

## Architecture

TCP fingerprinting uses two separate processes:

- **`huginn-ebpf-agent`** — loads the capture program (XDP or TC), attaches it to the
  network interface, and pins BPF maps to `/sys/fs/bpf/huginn/`. Runs once per node
  (DaemonSet in K8s, sidecar in Docker Compose). Requires elevated privileges but opens no ports.
  No Kubernetes Ingress integration; deploys as a standard container via raw manifests.

- **`huginn-proxy`** — opens the pinned BPF maps in read mode and injects the
  `x-tcp-p0f` header.

```
  huginn-ebpf-agent                      huginn-proxy
  ┌─────────────────────────┐           ┌─────────────────────────┐
  │ • Load capture program  │           │ • Open pinned maps      │
  │ • Attach to interface   │           │   (read-only)           │
  │ • Pin maps to bpffs     │           │ • Lookup per connection  │
  │ • Wait for SIGTERM      │           │ • Inject x-tcp-p0f      │
  └────────────┬────────────┘           └────────────▲───────────┘
               │                                       │
               │    /sys/fs/bpf/huginn/                │
               └──────────────┬────────────────────────┘
                              │
                    tcp_syn_map_v4/v6  (LruHashMap)
                    syn_counter        (Array)
                    syn_meta           (Array)
                    syn_insert_failures_v4/v6  (PerCpuArray)
                    syn_captured_v4/v6         (PerCpuArray)
                    syn_malformed_v4/v6        (PerCpuArray)
                    syn_rate_skipped_v4/v6     (PerCpuArray)
                    syn_rate_allowed_v4/v6     (PerCpuArray)
```

---

## Preconditions

### Kernel ≥ 5.11

Required for `CAP_BPF`-based loading. On kernels < 5.11, BPF memory uses `RLIMIT_MEMLOCK`
accounting (still supported but deprecated). Check: `uname -r`.

### One agent per node

Deploy the agent as a DaemonSet (K8s) or with `network_mode: "service:proxy"` (Docker Compose).
What happens if two agents do land on the same node depends on the backend, and none of the
outcomes are good:

| Backend                        | Second agent                                                                                                                                                     |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `xdp-native`, `xdp-skb`        | Attach fails with `EBUSY`. Only one XDP program per interface without a libxdp dispatcher.                                                                       |
| `tc` on kernel ≥ 6.6 (TCX) | If they share the same link pin, the second `attach_to_link` **replaces** the first program (last writer wins). If they attach without a shared pin, both stay attached and `syn_captured_*` double-count. |
| `tc` on kernel < 6.6 (netlink) | Both stay attached as separate clsact filters with different priorities. Same double-counting.                                                                   |

The `tc` cases are the dangerous ones: nothing errors and nothing logs, so a duplicated agent
looks healthy while inflating counters.

### Kernel ≥ 6.6 for TCX (backend `tc` only)

With `HUGINN_EBPF_CAPTURE=tc`, the agent chooses the attach mechanism at load time from the
running kernel and **logs + exports the result** as `capture_mode`:

| Kernel | `capture_mode` | Pinned `bpf_link` | Agent restart |
|---|---|---|---|
| ≥ 6.6 | `tcx` | yes (`{pin_path}/capture_link`, override with `HUGINN_EBPF_LINK_PIN_PATH`) | hitless: `attach_to_link` replaces the program on the same link |
| < 6.6 (or unreadable `uname`) | `netlink` | no (warning at start) | `drop(probe)` detaches; fresh captures pause until the new agent attaches |

There is no `tcx` value of `HUGINN_EBPF_CAPTURE`. Check with `uname -r` and the
`huginn_ebpf_capture_info` metric (`capture_mode`, `link_pinned`).

XDP (`xdp-native` / `xdp-skb`) uses aya's `bpf_link_create` path when the kernel accepts it
(typically ≥ 5.9) and pins that fd link the same way. If the kernel falls back to netlink XDP,
the agent logs a warning, does not pin, and restart detaches as before. Do not assume XDP
rollouts are hitless until `link_pinned="true"`.

### bpffs

`/sys/fs/bpf` must be mounted as bpffs on each node. Most modern Linux distributions
(systemd-based) do this automatically. Verify:

```bash
mount | grep bpffs
# Expected: bpffs on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime)
```

### CNI must preserve real client IP (Kubernetes)

The fingerprint correlates by `(src_ip, src_port)`. CNIs that SNAT traffic toward pods
(e.g. Flannel) break the correlation. Most production CNIs (Cilium, AWS VPC CNI, Calico BGP)
do not SNAT.

---

## Agent capabilities

The agent requires the following Linux capabilities and security settings:

| Capability / Setting   | Purpose                                                          |
|------------------------|------------------------------------------------------------------|
| `CAP_BPF`              | Create BPF maps and load BPF programs                            |
| `CAP_NET_ADMIN`        | Attach XDP program to a network interface                        |
| `CAP_PERFMON`          | Allow pointer arithmetic in BPF verifier                         |
| `seccomp: unconfined`  | Docker's default seccomp blocks the `bpf()` syscall              |
| `apparmor: unconfined` | Ubuntu/Debian's AppArmor profile blocks bpffs directory creation |

## Proxy capabilities

The proxy only reads pinned BPF maps:

| Capability | Purpose                                |
|------------|----------------------------------------|
| `CAP_BPF`  | Open pinned BPF maps via `BPF_OBJ_GET` |

No `seccomp:unconfined` or `apparmor:unconfined` needed.

---

## Configuration

### Agent environment variables

| Variable                                | Example              | Description                                                                                                                                                                                                                                                                                                                                                                                                                     |
|-----------------------------------------|----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `HUGINN_EBPF_INTERFACE`                 | `eth0`               | Network interface for the capture program (XDP or TC)                                                                                                                                                                                                                                                                                                                                                                           |
| `HUGINN_EBPF_DST_IP_V4`                 | `0.0.0.0`            | IPv4 destination filter (`0.0.0.0` = no filter)                                                                                                                                                                                                                                                                                                                                                                                 |
| `HUGINN_EBPF_DST_IP_V6`                 | `::`                 | IPv6 destination filter (`::` = no filter); quote in YAML if needed                                                                                                                                                                                                                                                                                                                                                             |
| `HUGINN_EBPF_DST_PORT`                  | `7000`               | Destination port filter (proxy listen port)                                                                                                                                                                                                                                                                                                                                                                                     |
| `HUGINN_EBPF_PIN_PATH`                  | `/sys/fs/bpf/huginn` | Pin directory (default shown)                                                                                                                                                                                                                                                                                                                                                                                                   |
| `HUGINN_EBPF_LINK_PIN_PATH`            | `{HUGINN_EBPF_PIN_PATH}/capture_link` | Pin path for the capture `bpf_link` (not a BPF map). Left in place on SIGTERM so the next agent can atomically replace the program. Unused on netlink attaches. Also the attach signal the proxy gate `stat()`s. |
| `HUGINN_EBPF_DRAIN_DELAY_SECS`         | `0` | Agent phase 1: publish `capture_state` draining and wait before `drop(probe)`. Size with `capture_poll_secs` + load-balancer detection + margin |
| `HUGINN_EBPF_HEARTBEAT_SECS`           | `1` | How often userspace bumps `capture_state.generation`. Must be a positive integer; used on the netlink path when there is no link pin |
| `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES`       | `8192`               | LRU map capacity (default shown). Agent-only: the agent publishes this value into the family-agnostic `syn_meta` map, and the proxy reads it from there for its staleness threshold — so it must not be set on the proxy.                                                                                                                                                                                                       |
| `HUGINN_EBPF_CAPTURE`                   | `xdp-native`         | Capture backend: `xdp-native` (driver XDP, default), `xdp-skb` (generic XDP, veth/loopback/VMs), or `tc` (clsact ingress; GRO-safe when native XDP is unavailable, e.g. VLAN/bond on generic XDP). Same BPF maps either way. There is no `tcx` value: `tc` attaches via TCX on kernel ≥ 6.6 and netlink below; the effective mechanism is `capture_mode` (see [Kernel ≥ 6.6 for TCX](#kernel--66-for-tcx-backend-tc-only)). |
| `HUGINN_EBPF_LOG_LEVEL`                 | `off`                | Verbosity of in-kernel `aya-log` datapath logging: `off` (default), `error`, `warn`, `info`, `debug`, `trace`. The kernel emits only records at/above the level (`debug` = per-capture, `warn` = map-insert failures), so the level gate runs in-kernel and `off` is zero-cost on the hot path. When non-`off` and `RUST_LOG` is unset, the agent defaults its filter to that level so records are shown. For diagnostics only. |
| `HUGINN_EBPF_HEALTH_FORMAT`            | `json`               | Body of `/health`, `/ready`, `/live`, and observability 404/500: `json` (default) or `text`. `/metrics` is never affected. See [TELEMETRY.md](TELEMETRY.md#health-body-format). |
| `HUGINN_EBPF_RATE_LIMIT_ENABLED`        | `false`              | Enable the in-kernel per-source-IP SYN rate limiter. When on, SYNs from an IP exceeding the threshold are skipped (not captured/fingerprinted); the packet still passes to the stack (never dropped). Uses a dual-buffer sliding-window Count-Min Sketch, hashed with a random seed drawn per agent load so the counter layout is not predictable from outside.                                                                 |
| `HUGINN_EBPF_RATE_LIMIT_BURST`          | `2000`               | Max SYNs per window per source IP before its SYNs stop being captured. Range `1..=65534`. Counted **per CPU**, and *not* the proxy's `[security.rate_limit] burst`: size it with [Sizing the SYN rate limiter](#sizing-the-syn-rate-limiter).                                                                                                                                                                                   |
| `HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS` | `1`                  | Sliding-window length in seconds. Range `1..=3600`. Once a source crosses `burst`, its SYNs are skipped until the window ends, so a long window means a long gap in that source's fingerprints.                                                                                                                                                                                                                                 |

> **Bad rate-limit value stops the agent**, like every other agent variable. An unset variable
> takes its default; one that is set but unusable exits with a message. With TCP fingerprinting
> on, the proxy `/ready` stays 503 (`capture_absent`) until the agent publishes `capture_state`.
> Check the agent log first if the proxy sits not-ready with that reason.

> **Scope and limits.** This shields the capture LRU from one loud source IP. It is **not** a
> network-level DoS defense, and it does nothing against a distributed flood where each source stays
> under the threshold, so the LRU can still saturate. A flood from enough distinct source IPs
> saturates every counter in the sketch instead, at which point *every* source reads over-limit and
> nothing gets fingerprinted - the limiter inverts from a filter into a capture kill-switch, visible
> as `tcp_syn_rate_skipped_total` climbing while `tcp_syn_rate_allowed_total` goes flat. The
> constant-memory sketch survives millions of spoofed IPs; its accuracy does not. The
> `syn_rate_skipped_*` /
> `syn_rate_allowed_*` counters are pinned, so their totals survive agent restarts; the counting
> sketch is not pinned and resets on every agent load. Its maps are allocated even with
> `ENABLED=false`.

#### Sizing the SYN rate limiter

`burst` caps how much of the capture LRU one source IP can claim, so size it against
`HUGINN_EBPF_SYN_MAP_MAX_ENTRIES`, never against a request rate. The map is shared by every client
and keyed `(source IP, source port)`, so one IP claims one entry per source port. Once it is full,
each insert evicts the least recently used entry, and the victim is whoever loses their entry before
the proxy reads it at accept time.

```
burst = HUGINN_EBPF_SYN_MAP_MAX_ENTRIES / (4 × cpus)
```

1. **Find `cpus`**, the number of CPUs one source's SYNs can reach. With a multi-queue NIC and the
   usual 4-tuple RSS hash, an IP varying its source ports lands on every RX queue, so use the
   interface's combined RX queue count. Fall back to the CPU count where there are no queues (veth,
   loopback, single-queue virtio).
2. **Divide, then clamp to `1..=65534`.** Outside that range the agent refuses to start.
3. **Verify against real traffic.** `tcp_syn_rate_skipped_total` should not increase under normal
   load; watch its rate, not its total, since the counter is pinned across restarts. If it climbs
   with no attack in progress, `burst` is too tight, usually a NAT gateway behind one IP (the sketch
   over-counts on hash collisions, never under-counts, so a gateway sharing cells with a flooder
   loses its signature early).

`burst` is enforced **per CPU** (each core has its own sketch, which keeps the datapath lock-free),
so one source's real ceiling is `burst × cpus`. That product is what you are sizing: as cores grow,
`burst` shrinks and the ceiling stays put.

| LRU            | `cpus`           | `burst` | Ceiling per source IP      |
|----------------|------------------|---------|----------------------------|
| 8192 (default) | 1 (veth in a VM) | `2048`  | 2048, a quarter of the map |
| 8192           | 4 queues         | `512`   | 2048, a quarter of the map |
| 8192           | 32 queues        | `64`    | 2048, a quarter of the map |
| 32768          | 8 queues         | `1024`  | 8192, a quarter of the map |

The `4 ×` is a conservative default, not a measured one: it caps one source at a quarter of the map
and leaves the rest for everyone else. Err on the low side. Going over only skips fingerprint
capture, so a tight `burst` costs TCP signatures for that source, not its traffic; a loose one costs
the protection entirely.

> The default `2000` is **not** a sized value, here or in `examples/docker-compose.ebpf.yml`. It is
> roughly right on a single-core host and too loose as soon as the host has several cores: on 8
> cores it allows 16000 SYNs per window against an 8192-entry LRU, so the limiter is on while one IP
> can still evict the whole map nearly twice over. Compute your own from the formula above.

#### Choosing a capture backend

Both hooks live in the same BPF object and share identical maps, key encoding, and value layout.
The proxy reads the same pinned maps regardless of backend. Only the kernel hook and attach
mechanism differ.

- **`xdp-native`** — driver-level XDP. Lowest overhead. Requires NIC driver XDP support.
- **`xdp-skb`** — generic XDP in the kernel stack. Works on veth/loopback/VMs.
- **`tc`** — TC classifier on ingress. Use when native XDP is unavailable (VLAN/bond, or when generic XDP would miss GRO packets). Attach is TCX or netlink from the kernel version; see [Kernel ≥ 6.6 for TCX](#kernel--66-for-tcx-backend-tc-only).

> Use `tc` when native XDP is not available and you would otherwise fall back to generic XDP
> (`xdp-skb`). Generic XDP does not handle GRO-aggregated (multi-buffer) packets: the program
> only sees the first segment and non-linear skbs are dropped. TC `clsact` ingress runs after GRO
> and reads the full skb via `bpf_skb_load_bytes`, so it is not affected. Capabilities are the
> same (`CAP_NET_ADMIN` + `CAP_BPF`/`CAP_PERFMON`); no new privileges required.

### Proxy configuration (`config.toml`)

```toml
[fingerprint]
tcp_enabled = true   # false = no BPF maps opened, no capabilities needed
```

| Variable                          | Example              | Description                                                                                                                                                                                            |
|-----------------------------------|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `HUGINN_EBPF_PIN_PATH`            | `/sys/fs/bpf/huginn` | Pin directory to read maps from (default shown)                                                                                                                                                        |
| `HUGINN_EBPF_LINK_PIN_PATH`       | `{pin_path}/capture_link` | Path the capture gate `stat()`s as proof of attach (same default as the agent) |
| `HUGINN_EBPF_CAPTURE_POLL_SECS`   | `1`                  | How often the capture gate refreshes. Minimum `1`; `0` is a startup error |
| `HUGINN_EBPF_CAPTURE_STALE_TICKS` | `3`                  | Polls without a `generation` bump before `capture_detached` (netlink path only) |
| `HUGINN_EBPF_RECONNECT_POLL_SECS` | `5`                  | Backstop poll interval for detecting recreated maps (e.g. a capacity change or a wiped bpffs); `0` disables automatic reconnection but **does not** stop the capture gate |

The proxy binds immediately. Until the agent publishes maps (and a non-zero `agent_boot_id` in
`capture_state`), `/ready` is 503 with `capture_absent` (after listeners are up). Lookups return
`SynResult::Miss` until the watcher opens the pins. See
[Runtime lifecycle and agent restarts](#runtime-lifecycle-and-agent-restarts).

---

## Docker Compose

See `examples/docker-compose.ebpf.yml` for the full working example.

The agent shares the proxy's network namespace (`network_mode: "service:proxy"`) so the
capture program on `eth0` sees the SYN packets arriving at the proxy. Both containers share
a bpffs Docker volume for map pinning.

```yaml
services:
  ebpf-agent:
    network_mode: "service:proxy"
    cap_add: [ CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON ]
    security_opt: [ seccomp:unconfined, apparmor:unconfined ]
    volumes:
      - bpffs:/sys/fs/bpf

  proxy:
    cap_add: [ CAP_BPF ]
    volumes:
      - bpffs:/sys/fs/bpf

volumes:
  bpffs:
    driver: local
    driver_opts:
      type: bpf
      o: ""
      device: bpffs
```

---

## Kubernetes

Example abbreviated manifests (raw YAML, no Helm chart or CRD provided). Both mount the
host's bpffs via `hostPath`.

```yaml
# Agent DaemonSet (abbreviated)
securityContext:
  capabilities:
    add: [ BPF, NET_ADMIN, PERFMON ]
  seccompProfile:
    type: Unconfined
volumeMounts:
  - name: bpffs
    mountPath: /sys/fs/bpf
volumes:
  - name: bpffs
    hostPath:
      path: /sys/fs/bpf
      type: DirectoryOrCreate

# Proxy Deployment (abbreviated)
securityContext:
  capabilities:
    add: [ BPF ]
  seccompProfile:
    type: RuntimeDefault
volumeMounts:
  - name: bpffs
    mountPath: /sys/fs/bpf
    readOnly: true
volumes:
  - name: bpffs
    hostPath:
      path: /sys/fs/bpf
      type: Directory
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full Kubernetes section.

---

## Runtime lifecycle and agent restarts

This section applies only with `ebpf-tcp` **and** `fingerprint.tcp_enabled = true`.

### Startup

The proxy binds immediately. `/ready` is 503 (`capture_absent`) until the agent publishes
`capture_state` (non-zero `agent_boot_id`). Lookups miss until the watcher opens the pins.

### Agent down, proxy still up

The proxy keeps its own map FDs. Those maps stay in the kernel even if the agent exits or the pin
files vanish. A lookup error is `SynResult::Miss` (no `x-tcp-p0f`); HTTP is never blocked.

| Attach | After the agent dies |
|--------|----------------------|
| Pinned `bpf_link` (TCX, XDP fd-link) | Program stays on the interface. The next agent replaces it with `attach_to_link`. |
| Netlink (TC on kernel &lt; 6.6, or XDP without `bpf_link_create`) | `drop(probe)` detaches. New fingerprints pause until the next agent attaches. |

`kubectl delete` of the DaemonSet is the same SIGTERM as a rollout: pins stay. The program can
keep running with no userspace owner until reboot, a new agent adopts the pin, or a future
`--cleanup` (not implemented). Uninstall does not mean the datapath is gone.

### Rollout: capture can continue while `/ready` blips

On SIGTERM the agent writes `lifecycle = draining`. The gate ranks that above a live link pin,
so every proxy on the node is 503 (`capture_draining`) until the next agent publishes `capturing`
with a new `agent_boot_id`. A SIGKILL mid-drain leaves the slot set.

```
HUGINN_EBPF_DRAIN_DELAY_SECS + HUGINN_EBPF_CAPTURE_POLL_SECS
  + load-balancer probe interval + new agent startup
```

In-flight connections keep going; the load balancer stops **new** traffic. Size rollouts with
`maxUnavailable: 1`. Capture never stopping is not the same as the proxy staying ready.

### Maps

Shutdown leaves map pins and the capture link pin. The next agent reopens the same kernel IDs
and, if a link pin exists, replaces the program in place.

Maps are recreated only when `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` changes (otherwise aya would keep
the old capacity). New IDs. The proxy compares published vs open IPv4/IPv6 IDs every
`HUGINN_EBPF_RECONNECT_POLL_SECS` (default 5; `0` disables this, not the capture gate) and swaps
atomically. A pin missing during recreate is transient: old maps stay until the next reconnect tick.

---

## HTTP keep-alives

Only TCP SYNs are captured. The fingerprint is looked up once at accept and reused for every
request on that connection, so **`x-tcp-p0f` is on all keep-alive requests**, not just the first.

No header (`SynResult::Miss`) means the SYN was never in the map (startup, eviction) or the entry
is stale (more than `2 × syn_map_max_entries` SYNs since capture). Capacity comes from the agent's
`syn_meta` map, not from which IP family is enabled.

`force_new_connection = true` opens a new TCP connection to the **backend**. It does not
recapture the client SYN.
