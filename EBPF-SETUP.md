# eBPF TCP SYN Fingerprinting - Setup Guide

TCP SYN fingerprinting is implemented via an XDP eBPF program that captures TCP SYN packets
and stores them in a BPF LRU hash map. The proxy looks up each connection's SYN data and
injects the `x-huginn-net-tcp` header with the p0f-style signature.

---

## Architecture

TCP fingerprinting uses two separate processes:

- **`huginn-ebpf-agent`** — loads the XDP program, attaches it to the network interface,
  and pins BPF maps to `/sys/fs/bpf/huginn/`. Runs once per node (DaemonSet in K8s,
  sidecar in Docker Compose). Requires elevated privileges but opens no ports.

- **`huginn-proxy`** — opens the pinned BPF maps in read mode and injects the
  `x-huginn-net-tcp` header. Runs as a standard Deployment with HPA.

```
  huginn-ebpf-agent                      huginn-proxy
  ┌─────────────────────────┐           ┌─────────────────────────┐
  │ • Load XDP program       │           │ • Open pinned maps      │
  │ • Attach to interface   │           │   (read-only)           │
  │ • Pin maps to bpffs     │           │ • Lookup per connection  │
  │ • Wait for SIGTERM      │           │ • Inject x-huginn-net-tcp│
  └────────────┬────────────┘           └────────────▲───────────┘
               │                                       │
               │    /sys/fs/bpf/huginn/                │
               └──────────────┬────────────────────────┘
                              │
                    tcp_syn_map_v4 (LruHashMap)
                    syn_counter (Array)
                    syn_insert_failures (Array)
```

---

## Preconditions

### Kernel ≥ 5.11

Required for `CAP_BPF`-based loading. On kernels < 5.11, BPF memory uses `RLIMIT_MEMLOCK`
accounting (still supported but deprecated). Check: `uname -r`.

### One agent per node

Linux allows only one XDP program attached to a network interface at a time. If two agents
run on the same node, the second replaces the first's XDP program. Deploy the agent as a
DaemonSet (K8s) or with `network_mode: "service:proxy"` (Docker Compose).

### IPv4 listen address

The XDP program captures only `ETH_P_IP` (IPv4) packets. Configuring the proxy to listen on
an IPv6 address with `tcp_enabled = true` causes a hard startup failure.

This is not a limitation in practice when a load balancer or ingress sits in front: the proxy
only sees IPv4 connections internally regardless of the original client protocol.

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
| `HUGINN_EBPF_INTERFACE` | `eth0` | Network interface to attach XDP to |
| `HUGINN_EBPF_DST_IP_V4` | `0.0.0.0` | IPv4 destination filter (`0.0.0.0` = no filter) |
| `HUGINN_EBPF_DST_IP_V6` | `::` | IPv6 destination filter (`::` = no filter); quote in YAML if needed |
| `HUGINN_EBPF_DST_PORT` | `7000` | Destination port filter (proxy listen port) |
| `HUGINN_EBPF_PIN_PATH` | `/sys/fs/bpf/huginn` | Pin directory (default shown) |
| `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` | `8192` | LRU map capacity (default shown) |
| `HUGINN_EBPF_XDP_MODE` | `native` | XDP attach mode: `native` (default, driver-level) or `skb` (generic, for veth/loopback) |

### Proxy configuration (`config.toml`)

```toml
[fingerprint]
tcp_enabled = true   # false = no BPF maps opened, no capabilities needed
```

| Variable | Example | Description |
|---|---|---|
| `HUGINN_EBPF_PIN_PATH` | `/sys/fs/bpf/huginn` | Pin directory to read maps from (default shown) |

The proxy retries opening pinned maps on startup (up to 60 seconds) to handle the case
where the agent starts after the proxy.

---

## Docker Compose

See `examples/docker-compose.yml` for the full working example.

The agent shares the proxy's network namespace (`network_mode: "service:proxy"`) so XDP
on `eth0` captures the SYN packets arriving at the proxy. Both containers share a bpffs
Docker volume for map pinning.

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

The agent runs as a **DaemonSet** (one per node). The proxy runs as a **Deployment** with
HPA. Both mount the host's bpffs via `hostPath`.

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

A dev-only workspace example loads the XDP ELF and checks that expected maps exist. It needs `CAP_BPF` to create BPF maps. Build as your user, then run the binary with sudo (so `cargo` is not needed under sudo):

```bash
cargo build -p bpf-test
sudo ./target/debug/bpf-test
```

Expected output on success:
```
INFO Loading XDP ELF and checking maps...
INFO   map 'tcp_syn_map_v4' OK
INFO   map 'syn_counter' OK
INFO   map 'syn_insert_failures' OK
INFO SUCCESS: ELF loaded and all expected maps present
```

If you get `PermissionDenied` on map creation:

```bash
# Is unprivileged BPF disabled? (0 = allowed, 1/2 = restricted)
sudo cat /proc/sys/kernel/unprivileged_bpf_disabled

# Recent BPF-related kernel messages
sudo dmesg | grep -i bpf | tail -10

# Check process capabilities
cat /proc/self/status | grep Cap
```
