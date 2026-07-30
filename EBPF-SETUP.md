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

Linux allows only one XDP or TC clsact program attached to a network interface at a time.
If two agents run on the same node, the second replaces the first's program. Deploy the
agent as a DaemonSet (K8s) or with `network_mode: "service:proxy"` (Docker Compose).

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

| Capability / Setting | Purpose |
|---|---|
| `CAP_BPF` | Create BPF maps and load BPF programs |
| `CAP_NET_ADMIN` | Attach XDP program to a network interface |
| `CAP_PERFMON` | Allow pointer arithmetic in BPF verifier |
| `seccomp: unconfined` | Docker's default seccomp blocks the `bpf()` syscall |
| `apparmor: unconfined` | Ubuntu/Debian's AppArmor profile blocks bpffs directory creation |

## Proxy capabilities

The proxy only reads pinned BPF maps:

| Capability | Purpose |
|---|---|
| `CAP_BPF` | Open pinned BPF maps via `BPF_OBJ_GET` |

No `seccomp:unconfined` or `apparmor:unconfined` needed.

---

## Configuration

### Agent environment variables

| Variable | Example | Description |
|---|---|---|
| `HUGINN_EBPF_INTERFACE` | `eth0` | Network interface for the capture program (XDP or TC) |
| `HUGINN_EBPF_DST_IP_V4` | `0.0.0.0` | IPv4 destination filter (`0.0.0.0` = no filter) |
| `HUGINN_EBPF_DST_IP_V6` | `::` | IPv6 destination filter (`::` = no filter); quote in YAML if needed |
| `HUGINN_EBPF_DST_PORT` | `7000` | Destination port filter (proxy listen port) |
| `HUGINN_EBPF_PIN_PATH` | `/sys/fs/bpf/huginn` | Pin directory (default shown) |
| `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` | `8192` | LRU map capacity (default shown). Agent-only: the agent publishes this value into the family-agnostic `syn_meta` map, and the proxy reads it from there for its staleness threshold — so it must not be set on the proxy. |
| `HUGINN_EBPF_CAPTURE` | `xdp-native` | Capture backend: `xdp-native` (driver XDP, default), `xdp-skb` (generic XDP, veth/loopback/VMs), or `tc` (clsact ingress; GRO-safe when native XDP is unavailable, e.g. VLAN/bond on generic XDP). Same BPF maps either way. |
| `HUGINN_EBPF_LOG_LEVEL` | `off` | Verbosity of in-kernel `aya-log` datapath logging: `off` (default), `error`, `warn`, `info`, `debug`, `trace`. The kernel emits only records at/above the level (`debug` = per-capture, `warn` = map-insert failures), so the level gate runs in-kernel and `off` is zero-cost on the hot path. When non-`off` and `RUST_LOG` is unset, the agent defaults its filter to that level so records are shown. For diagnostics only. |
| `HUGINN_EBPF_RATE_LIMIT_ENABLED` | `false` | Enable the in-kernel per-source-IP SYN rate limiter (`true`/`false`). When on, SYNs from an IP exceeding the threshold are skipped (not captured/fingerprinted); the packet still passes to the stack (never dropped). Uses a dual-buffer sliding-window Count-Min Sketch. |
| `HUGINN_EBPF_RATE_LIMIT_BURST` | `2000` | Max SYNs per window per source IP before its SYNs stop being captured (skipped, not dropped). Counted **per CPU**, see [Sizing the SYN rate limiter](#sizing-the-syn-rate-limiter). The default is only sensible on a low-core host, and this is *not* the proxy's `[security.rate_limit] burst`. Must be `1..=65534`, because the sketch counts in `u16`: a window's own count cannot cross a larger threshold, so the limiter stops firing. |
| `HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS` | `1` | Sliding-window length in seconds. Must be `1..=3600`. Counts only age out when the window rotates, and the `u16` counters saturate long before that on a long window, so a source that reaches `burst` stays uncaptured for the rest of it: past an hour the limiter is a blocklist, not a rate limit. |

> **Bad rate-limit values are not fatal.** All three are trimmed and lowercased first, so `TRUE` or
> a stray newline out of a `.env` file parses fine. An unusable `ENABLED`, `BURST` or
> `WINDOW_SECONDS` is logged at `ERROR`, naming the variable, the rejected value, the accepted range
> and the default used in its place.
> The agent starts anyway. Exiting would leave the proxy blocked waiting for pinned maps that
> never appear, so one bad value would also take down HTTP and TLS fingerprinting. Grep the agent
> log for `invalid eBPF rate-limit configuration` after a config change: a rejected `BURST` or
> `WINDOW_SECONDS` means the limiter is running with the default, not what you asked for, and a
> rejected `ENABLED` means it is off entirely.

> **What the rate limiter protects.** Over-limit SYNs are *skipped* (not fingerprinted into the
> `tcp_syn_map_v4/v6` capture LRU), never dropped - the packet always reaches the TCP stack. So
> this shields the capture LRU from a single loud source IP; it is **not** a network-level DoS
> defense. It also does nothing against a spoofed/distributed flood where each source sends only a
> few SYNs (each stays under the threshold), so the capture LRU can still saturate under that
> pattern. The threshold is enforced **per CPU** (the sketch is a per-CPU map), so the real ceiling
> for one source is roughly `burst × num_cpus` per window. See
> [Sizing the SYN rate limiter](#sizing-the-syn-rate-limiter).
>
> The counting sketch (`syn_rate_sketch_v4/v6`) is **not pinned**: it is ephemeral per-CPU state
> and resets to empty on every agent (re)load. The cumulative `syn_rate_skipped_*` /
> `syn_rate_allowed_*` counters **are** pinned, so their totals survive agent restarts.
>
> **The sketch maps are allocated even with the limiter off.** They are part of the single BPF
> object the agent loads, so the kernel reserves them regardless of `ENABLED`: 16400 bytes per CPU
> per family, i.e. `16400 × cpus × 2`. Per-CPU maps are sized by *possible* CPUs, not online ones,
> so read `cpus` from `/sys/devices/system/cpu/possible`: roughly 260 KiB at 8, 2 MiB at 64. A VM
> reporting many more possible than online CPUs pays for the possible ones. Turning the limiter off
> costs nothing on the packet path (one global read and an early return) but does not give this
> memory back.

#### Sizing the SYN rate limiter

Size `burst` against the capture LRU, not against a request rate:

```
burst = HUGINN_EBPF_SYN_MAP_MAX_ENTRIES / (4 × cpus)
```

`burst` is enforced **per CPU** (each core has its own sketch, which is what keeps the datapath
lock-free), so the real ceiling for one source is `burst × cpus`. The formula holds that ceiling at
~25 % of the LRU whatever the core count: you are sizing `burst × cpus`, not `burst`.

| `cpus` | `burst` (8192-entry LRU) | Ceiling per source IP |
|---|---|---|
| 1 | `2048` | 2048 per window |
| 8 | `256` | 2048 per window |
| 64 | `32` | 2048 per window |

Capping the share matters because the capture map is a fixed-size LRU shared by every client, keyed
`(source IP, source port)`. One IP claims one entry per source port, and once the map is full each
insert evicts the least recently used entry. The proxy reads an entry once, at accept time, so a
flood that evicts other clients' entries first strips *their* fingerprints, not its own. The `4 ×`
in the formula is the headroom choice: one source may claim a quarter of the map, leaving the rest
for everyone else.

Take `cpus` from the combined queue count in `ethtool -l`: with a multi-queue NIC and the usual
4-tuple RSS hash, one IP varying source ports reaches every queue. Use the CPU count if there are no
queues to read. Cap the result at 65534; above that the agent logs an `ERROR` and falls back to the
default.

Err on the low side. Going over only skips *fingerprint capture*: the SYN still reaches the TCP
stack and the connection completes, so a tight `burst` costs TCP signatures for that source, not its
traffic. A loose one costs the protection entirely. The sketch also over-counts on hash collisions
(never under-counts), so a busy NAT gateway sharing cells with a flooder can lose its signature
early, which is the same mild failure.

Then check against real traffic: `tcp_syn_rate_skipped_total` should not increase under normal load.
Watch its rate, not its absolute value, since the counter is pinned and keeps earlier totals. If it
climbs with no attack in progress, `burst` is too tight, usually a NAT gateway behind one IP.

> The default `2000` is **not** a sized value, here or in `examples/docker-compose.ebpf.yml`. It is
> roughly right on a single-core host and too loose everywhere else: on 8 cores it allows 16000 SYNs
> per window against an 8192-entry LRU, so the limiter is on while one IP can still evict the whole
> map nearly twice over. Compute your own from the formula above.

#### Choosing a capture backend

Both hooks live in the same BPF object and share identical maps, key encoding, and value layout.
The proxy reads the same pinned maps regardless of backend. Only the kernel hook and attach
mechanism differ.

- **`xdp-native`** — driver-level XDP. Lowest overhead. Requires NIC driver XDP support.
- **`xdp-skb`** — generic XDP in the kernel stack. Works on veth/loopback/VMs.
- **`tc`** — TC `clsact` **ingress** classifier. Reads packet bytes via `bpf_skb_load_bytes`
  (GRO-safe) and returns `TC_ACT_OK`, so it **never drops** packets and works on **VLAN/bond**
  interfaces.

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

| Variable | Example | Description |
|---|---|---|
| `HUGINN_EBPF_PIN_PATH` | `/sys/fs/bpf/huginn` | Pin directory to read maps from (default shown) |
| `HUGINN_EBPF_RECONNECT_POLL_SECS` | `5` | Backstop poll interval for detecting recreated maps (e.g. a capacity change or a wiped bpffs); `0` disables automatic reconnection. Normal agent restarts reuse the same maps and need no reconnection |

At startup the proxy retries opening the pinned maps with a fixed backoff until the agent has
pinned them, so the two containers can start in any order. See
[Runtime lifecycle and agent restarts](#runtime-lifecycle-and-agent-restarts) for how the proxy
behaves once connected.

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
    cap_add: [CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON]
    security_opt: [seccomp:unconfined, apparmor:unconfined]
    volumes:
      - bpffs:/sys/fs/bpf

  proxy:
    cap_add: [CAP_BPF]
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
    add: [BPF, NET_ADMIN, PERFMON]
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
    add: [BPF]
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

The proxy only reads maps when TCP fingerprinting is active — that is, built with the `ebpf-tcp`
feature **and** `fingerprint.tcp_enabled = true`. Otherwise no maps are opened and none of the
behavior below applies.

### Startup

The proxy retries `from_pinned` with a fixed backoff until the agent's pins appear. This wait
only affects the proxy's own readiness (it does not mark `/ready` until listeners are accepting);
the observability server is already up and answering `/health` and `/metrics` during the wait.

### Agent crash while the proxy is connected

The proxy **does not crash** if the agent dies after the maps are connected:

- The proxy holds its own file descriptors to the map objects. The kernel keeps a map alive while
  any reference exists, so it survives the agent process exiting and even the pin files being
  removed.
- Every lookup degrades gracefully: any read error returns `SynResult::Miss`, so the
  `x-tcp-p0f` header is simply not injected. Request forwarding is never blocked or dropped.

The trade-off is a loss of **fresh** captures: the agent owns the attached XDP/TC program, so when
it exits the program is detached and no new SYNs are written. Existing traffic keeps flowing;
new connections just stop getting a fingerprint until a healthy agent is capturing again.

### Agent restart: map reuse (no reconnection gap)

The agent pins its maps via `map_pin_path` and **leaves the pins in place on shutdown**. When it
restarts it reuses the existing pinned maps instead of creating new ones, so the kernel IDs stay
the same and the maps keep their contents. A proxy that already holds those maps therefore needs to
do nothing, there is no reconnection window, and captures written just before and after the
restart share one continuous map.

The only case that recreates the maps is a **capacity change**: if `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES`
differs from the pinned SYN maps, the agent drops all pins on startup so the loader recreates them
at the new size (aya would otherwise silently reuse the old capacity). The recreated maps get new
kernel IDs.

### Automatic reconnection (backstop)

The proxy periodically compares the kernel IDs of the pinned IPv4 and IPv6 SYN maps with the IDs of
its open maps. If either ID changes — a capacity change as above, or an operator/node wiping bpffs —
it opens a complete fresh map set and swaps it atomically without dropping connections.

The recovery window is bounded by `HUGINN_EBPF_RECONNECT_POLL_SECS` (5 seconds by default). A pin
that is temporarily absent while the agent is recreating maps is treated as transient: the proxy
retains its previous maps and retries on the next poll. Set the interval to `0` to disable automatic
reconnection; in that mode a map recreation again requires restarting the proxy.

---

## HTTP keep-alives

The capture program intercepts only TCP SYN packets. The fingerprint is looked up once at TCP
accept time and reused for every request on that connection. As a result, **`x-tcp-p0f` is
present on all requests** of a keep-alive connection, not just the first.

A `SynResult::Miss` (no header injected) happens when:
- the SYN was not captured (proxy just started, map entry evicted), or
- the entry is stale (more than `2 x syn_map_max_entries` SYNs arrived since capture). The proxy
  reads `syn_map_max_entries` from the family-agnostic `syn_meta` map the agent publishes, so the
  threshold always matches the agent's capacity and does not depend on which IP family is enabled.

`force_new_connection = true` is unrelated to fingerprint availability: it controls whether
the proxy opens a new TCP connection to the **backend** per request, not whether the client
SYN is re-captured.
