# eBPF TCP SYN Fingerprinting — Setup Guide

TCP SYN fingerprinting is implemented via an XDP eBPF program that captures TCP SYN packets
and stores them in a BPF LRU hash map. The proxy looks up each connection's SYN data and
injects the `x-huginn-net-tcp` header with the p0f-style signature.

---

## Preconditions

### Kernel ≥ 5.11

Required. On kernels < 5.11 BPF memory uses `RLIMIT_MEMLOCK` accounting, which is not
supported. Check your host: `uname -r`.

### One instance per node

Linux allows only one XDP program attached to a network interface at a time. If two instances
run on the same node, the second replaces the first's XDP program and each has its own private
BPF map — the instance that lost the attachment stops receiving SYNs and never injects the
header. Deploy as a DaemonSet (one pod per node) or one container per host.

### IPv4 listen address

The XDP program captures only `ETH_P_IP` (IPv4) packets. Configuring the proxy to listen on
an IPv6 address with `tcp_enabled = true` causes a hard startup failure.

This is not a limitation in practice when a load balancer or ingress (Traefik, NGINX, K8s
Ingress) sits in front: the proxy only sees IPv4 connections internally regardless of whether
the original client used IPv4 or IPv6.

### Linux capabilities

Three capabilities are required. The binary has them set via `setcap` in the Dockerfile, but
the container or pod must also include them in its bounding set:

| Capability | Purpose |
|---|---|
| `CAP_BPF` | Create BPF maps and load BPF programs |
| `CAP_NET_ADMIN` | Attach XDP program to a network interface |
| `CAP_PERFMON` | Allow pointer arithmetic in XDP (required by BPF verifier for non-root) |

### Seccomp

Docker's default seccomp profile blocks the `bpf()` syscall. Use `seccomp:unconfined` or a
custom profile that allows the `bpf` syscall.

### CNI must preserve real client IP (Kubernetes)

The fingerprint correlates by `(src_ip, src_port)`. CNIs that SNAT traffic toward pods
(e.g. Flannel) break the correlation. Most production CNIs (Cilium, AWS VPC CNI, Calico BGP)
do not SNAT.

---

## Configuration

### `config.toml`

```toml
[fingerprint]
tcp_enabled = true   # false = eBPF not initialized, no capabilities needed
```

### Environment variables

Required when `tcp_enabled = true`. Missing variables cause a hard startup failure.

| Variable | Example | Description |
|---|---|---|
| `HUGINN_EBPF_INTERFACE` | `eth0` | Network interface to attach XDP to |
| `HUGINN_EBPF_DST_IP` | `0.0.0.0` | Destination IP filter. `0.0.0.0` = no filter |
| `HUGINN_EBPF_DST_PORT` | `7000` | Destination port filter (must match proxy listen port) |

---

## Docker Compose

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

See `examples/docker-compose.yml` for the full working example.

---

## Kubernetes

Deploy as a **DaemonSet — one pod per node, no HPA**. The proxy handles all traffic on the
node and the eBPF probe captures SYNs on that node's interface.

```yaml
securityContext:
  capabilities:
    add:
      - CAP_BPF
      - CAP_NET_ADMIN
      - CAP_PERFMON
  seccompProfile:
    type: Unconfined
```

> A decoupled eBPF agent (probe running as a separate DaemonSet container sharing maps via
> `/sys/fs/bpf/`) is not yet implemented and is not on the current roadmap.

---

## HTTP keep-alives

XDP captures only TCP SYN packets. The fingerprint is looked up once at TCP accept time and
reused for every request on that connection. As a result, **`x-huginn-net-tcp` is present on
all requests** of a keep-alive connection — not just the first.

A `SynResult::Miss` (no header injected) happens when:
- the SYN was not captured (proxy just started, stale entry, IPv6 client), or
- the BPF map entry was evicted before the connection was accepted (very high load).

`force_new_connection = true` is unrelated to fingerprint availability — it controls whether
the proxy opens a new TCP connection to the **backend** per request, not whether the client
SYN is re-captured.

---

## Verify the setup

The diagnostic binary needs `CAP_BPF` to create BPF maps. Two options:

**build first, then run with sudo:**
```bash
cargo build -p huginn-proxy-ebpf --bin bpf_test
sudo ./target/debug/bpf_test
```
```

Expected output on success:
```
INFO Testing BPF map creation with aya...
INFO SUCCESS: BPF ELF loaded and all maps created OK
```

If you get `PermissionDenied` on map creation, BPF syscall is being blocked:

```bash
# Is unprivileged BPF disabled? (0 = allowed, 1/2 = restricted)
sudo cat /proc/sys/kernel/unprivileged_bpf_disabled

# Recent BPF-related kernel messages
sudo dmesg | grep -i bpf | tail -10

# Check process capabilities
cat /proc/self/status | grep Cap
```
