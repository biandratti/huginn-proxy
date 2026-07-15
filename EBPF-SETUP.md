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
                    syn_insert_failures_v4/v6  (PerCpuArray)
                    syn_captured_v4/v6         (PerCpuArray)
                    syn_malformed_v4/v6        (PerCpuArray)
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
| `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` | `8192` | LRU map capacity (default shown) |
| `HUGINN_EBPF_CAPTURE` | `xdp-native` | Capture backend: `xdp-native` (driver XDP, default), `xdp-skb` (generic XDP, veth/loopback/VMs), or `tc` (clsact ingress; GRO-safe when native XDP is unavailable, e.g. VLAN/bond on generic XDP). Same BPF maps either way. |
| `HUGINN_EBPF_LOG_LEVEL` | `off` | Verbosity of in-kernel `aya-log` datapath logging: `off` (default), `error`, `warn`, `info`, `debug`, `trace`. The kernel emits only records at/above the level (`debug` = per-capture, `warn` = map-insert failures), so the level gate runs in-kernel and `off` is zero-cost on the hot path. When non-`off` and `RUST_LOG` is unset, the agent defaults its filter to that level so records are shown. For diagnostics only. |

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
| `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` | `8192` | LRU map capacity used by the agent; the proxy uses the same value for stale-entry detection |
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
- the entry is stale (more than `2 x syn_map_max_entries` SYNs arrived since capture).

`force_new_connection = true` is unrelated to fingerprint availability: it controls whether
the proxy opens a new TCP connection to the **backend** per request, not whether the client
SYN is re-captured.
