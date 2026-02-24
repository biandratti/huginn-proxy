# eBPF TCP SYN Fingerprinting — Setup Guide

TCP SYN fingerprinting is implemented via an XDP eBPF program that captures TCP SYN packets
and stores them in a BPF LRU hash map. The proxy looks up each connection's SYN data and
injects the `x-huginn-net-tcp` header with the p0f-style signature.

**This solution requires exactly one instance per node.** Linux allows only one XDP program
attached to a network interface at a time. If two instances run on the same node:

- The second one replaces the first's XDP program on the interface.
- Each instance has its own private BPF map — maps are not shared between processes.
- The instance that lost the XDP attachment stops receiving SYNs; its map lookups always
  return `None` and the `x-huginn-net-tcp` header is never injected.

Currently, the eBPF probe runs **inside the proxy process** — there is no separate agent.
In Docker Compose this means one proxy container per host. A DaemonSet deployment would
require either running the full proxy as a DaemonSet, or decoupling the eBPF probe into a
standalone agent that shares BPF maps with the proxy via a pinned path (`/sys/fs/bpf/`).
That decoupled model is not yet implemented and it is not part for the current ROADMAP.

## Known limitations

### IPv4 only

The XDP program captures only `ETH_P_IP` (IPv4) packets. IPv6 packets are passed through
without fingerprinting. As a result:

- `tcp_enabled = true` requires the proxy to listen on an IPv4 address. Configuring an IPv6
  listen address causes a hard startup failure.
- IPv6 clients that connect **directly** to the proxy are not fingerprinted — the connection
  works but `x-huginn-net-tcp` will not be injected.

**In practice this is not a limitation** for most deployments: when a load balancer or
ingress (Traefik, NGINX, K8s Ingress) sits in front and terminates external connections,
the proxy only sees IPv4 connections internally — regardless of whether the client connected
over IPv4 or IPv6. The fingerprint is captured correctly in this setup.

Only direct IPv6 exposure (proxy reachable via `::` without an intermediary) is affected.

---

## Requirements

### Kernel

| Kernel | BPF memory | XDP support | Status |
|---|---|---|---|
| < 4.18 | `RLIMIT_MEMLOCK` | Partial | ❌ Not supported |
| 4.18 – 5.10 | `RLIMIT_MEMLOCK` | Full | ✅ Needs `ulimits: memlock: -1` |
| ≥ 5.11 | cgroup memory | Full | ✅ `ulimits` is a no-op |

Check your host kernel: `uname -r`

### Linux Capabilities

Three capabilities are required. The binary has them set via `setcap` (Dockerfile), but
the container/pod must also include them in its bounding set:

| Capability | Purpose |
|---|---|
| `CAP_BPF` | Create BPF maps and load BPF programs |
| `CAP_NET_ADMIN` | Attach XDP program to a network interface |
| `CAP_PERFMON` | Allow pointer arithmetic in XDP (required by BPF verifier for non-root) |

### Syscall filter (seccomp)

Docker's default seccomp profile blocks the `bpf()` syscall. Either:
- Use `seccomp:unconfined` (simplest, less restrictive), or
- Use a custom seccomp profile that allows `bpf` syscall.

---

## Configuration

### `config.toml` (application)

```toml
[fingerprint]
tcp_enabled = true   # false = eBPF not initialized, no capabilities needed
```

### Environment variables (infrastructure)

Required when `tcp_enabled = true`. Missing variables cause a hard startup failure.

| Variable | Example | Description |
|---|---|---|
| `HUGINN_EBPF_INTERFACE` | `eth0` | Network interface to attach XDP to |
| `HUGINN_EBPF_DST_IP` | `0.0.0.0` | Destination IP filter. `0.0.0.0` = no filter |
| `HUGINN_EBPF_DST_PORT` | `7000` | Destination port filter (must match proxy listen port) |

---

## Docker Compose

**Kernel ≥ 5.11**:

```yaml
services:
  proxy:
    environment:
      - HUGINN_EBPF_INTERFACE=eth0
      - HUGINN_EBPF_DST_IP=0.0.0.0
      - HUGINN_EBPF_DST_PORT=7000
    cap_add:
      - CAP_BPF
      - CAP_NET_ADMIN
      - CAP_PERFMON
    security_opt:
      - seccomp:unconfined
```

**Kernel < 5.11** add `ulimits`:

```yaml
services:
  proxy:
    environment:
      - HUGINN_EBPF_INTERFACE=eth0
      - HUGINN_EBPF_DST_IP=0.0.0.0
      - HUGINN_EBPF_DST_PORT=7000
    cap_add:
      - CAP_BPF
      - CAP_NET_ADMIN
      - CAP_PERFMON
    security_opt:
      - seccomp:unconfined
    ulimits:
      memlock:
        soft: -1
        hard: -1
```

> **Why `ulimits` + programmatic `setrlimit`?**
> `EbpfProbe::new` calls `setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)` at startup, but
> `setrlimit` cannot exceed the container's hard limit. Without `ulimits: memlock: hard: -1`,
> Docker caps the hard limit at 64KB and the programmatic call fails silently on kernels < 5.11.
> On kernels ≥ 5.11 both are no-ops (BPF uses cgroup memory accounting instead).

---

## Kubernetes

The intended deployment model is a **DaemonSet — one pod per node, no HPA**. the proxy handles all traffic on the node and the eBPF probe captures SYNs on that node's interface.
No cross-node coordination is needed.

Requirements for the pod:

- **Capabilities** — `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` must be granted via
  `securityContext.capabilities.add`.
- **seccomp** — `RuntimeDefault` blocks `bpf()`. Use `seccompProfile: type: Unconfined`
  or a custom profile that allows the `bpf` syscall.
- **CNI must preserve real client IP** — the fingerprint correlates by `(src_ip, src_port)`.
  CNIs that SNAT traffic toward pods (e.g. Flannel) will break correlation. Most production
  CNIs (Cilium, AWS VPC CNI, Calico BGP) do not SNAT.

Known limitations not yet addressed:

- CNIs with SNAT (Flannel) — `hostNetwork: true` is a candidate mitigation, not yet tested.
- Decoupled eBPF agent — currently the probe runs inside the proxy process; running it as a
  separate DaemonSet container sharing maps via `/sys/fs/bpf/` is not yet implemented.

---

## HTTP keep-alives

XDP captures only TCP SYN packets. The second (and subsequent) requests on a keep-alive
connection do not generate a new SYN, so the `x-huginn-net-tcp` header is **only present on
the first request** of each connection.

To guarantee a fingerprint on every request, enable `force_new_connection = true` per route:

```toml
[[routes]]
# ...
force_new_connection = true   # new TCP+TLS handshake per request → new SYN → always has fingerprint
```

> This adds latency per request (benchmark pending — see ROADMAP.md).

---

## Verify the setup

Run the diagnostic binary on the host (requires root or the same capabilities):

```bash
# Default log level (info)
sudo -E cargo run -p huginn-proxy-ebpf --bin bpf_test

# With debug output
sudo -E cargo run -p huginn-proxy-ebpf --bin bpf_test -- debug

# Or via RUST_LOG
RUST_LOG=debug sudo -E cargo run -p huginn-proxy-ebpf --bin bpf_test
```

Expected output on success:
```
INFO Testing BPF map creation with aya...
INFO SUCCESS: BPF ELF loaded and all maps created OK
```

Useful kernel checks if it fails:

```bash
# Is unprivileged BPF disabled?
sudo cat /proc/sys/kernel/unprivileged_bpf_disabled

# Recent BPF-related kernel messages
sudo dmesg | grep -i bpf | tail -10

# Check process capabilities
cat /proc/self/status | grep Cap
```
