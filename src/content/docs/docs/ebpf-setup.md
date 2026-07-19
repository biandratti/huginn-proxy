---
title: eBPF TCP setup
description: XDP or TC capture agent, pinned maps, and kernel requirements for TCP SYN fingerprints.
sidebar:
  order: 32
---

TCP SYN fingerprinting uses an eBPF program (**XDP** or **TC clsact**) loaded by **`huginn-ebpf-agent`**. The agent pins BPF maps under **bpffs** (for example under `HUGINN_EBPF_PIN_PATH`). **Huginn Proxy** opens those maps read-only and emits `x-tcp-p0f`. Both backends share the same maps; the proxy does not care which hook is attached.

## Architecture

Two processes cooperate:

1. **eBPF agent** (`huginn-ebpf-agent`): loads the capture program (XDP or TC), attaches it to the interface, pins maps, exposes metrics, stays running.
2. **Proxy** (`huginn-proxy`): accepts connections, looks up `(src_ip, src_port)` in the map, formats the p0f-style signature.

## Preconditions

- **Kernel ≥ 5.11** (recommended for current BPF UAPI).
- **bpffs** mounted at `/sys/fs/bpf` (Compose uses a `bpf` volume; on bare metal ensure the mount exists).
- **One agent per node / interface**: Linux allows only one XDP or TC clsact program on a given NIC; a second loader replaces the first.

## Capabilities

| Component | Typical needs |
| --- | --- |
| **eBPF agent** | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` (or root); often **seccomp/apparmor unconfined** so `bpf()` and attach succeed in containers. |
| **Proxy** | **`CAP_BPF`** is enough when it only **opens** pinned maps (no program load in the proxy process). |

## Environment variables

### Agent

| Variable | Role |
| --- | --- |
| `HUGINN_EBPF_INTERFACE` | NIC to attach to (in Docker Compose with `network_mode: service:proxy`, this is the **proxy** container’s `eth0`). |
| `HUGINN_EBPF_DST_PORT` | Listener port to filter toward (the proxy’s TLS/HTTP port, e.g. `7000`). |
| `HUGINN_EBPF_DST_IP_V4` | IPv4 destination filter (`0.0.0.0` = no filter). |
| `HUGINN_EBPF_DST_IP_V6` | IPv6 counterpart (`::` = no filter; quote in YAML if needed). |
| `HUGINN_EBPF_PIN_PATH` | Directory under bpffs where maps are pinned (e.g. `/sys/fs/bpf/huginn`). **Same** on proxy. |
| `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` | LRU map capacity. **Agent-only**: published into `syn_meta` for the proxy; do **not** set this on the proxy. |
| `HUGINN_EBPF_CAPTURE` | Capture backend: `xdp-native` (default), `xdp-skb`, or `tc`. See [Choosing a capture backend](#choosing-a-capture-backend). |
| `HUGINN_EBPF_LOG_LEVEL` | In-kernel datapath log level: `off` (default), `error`, `warn`, `info`, `debug`, `trace`. Diagnostics only. |
| `HUGINN_EBPF_METRICS_ADDR` / `HUGINN_EBPF_METRICS_PORT` | Where the **agent** binds `/metrics`, `/health`, `/ready`, `/live`. |

### Proxy

| Variable | Role |
| --- | --- |
| `HUGINN_EBPF_PIN_PATH` | Pin directory to read maps from (must match the agent). |
| `HUGINN_EBPF_RECONNECT_POLL_SECS` | Poll interval for detecting recreated maps (default `5`; `0` disables). Normal agent restarts reuse the same maps and need no reconnection. |

Also set `fingerprint.tcp_enabled = true` in config. Full stack layout (Compose, caps, volumes): [`examples/docker-compose.ebpf.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.ebpf.yml) and [`examples/docker-compose.release-ebpf.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.release-ebpf.yml).

### Choosing a capture backend

Both hooks live in the same BPF object and share identical maps. Only the kernel hook differs:

- **`xdp-native`**: driver-level XDP. Lowest overhead. Needs NIC driver XDP support.
- **`xdp-skb`**: generic XDP in the kernel stack. Works on veth/loopback/VMs.
- **`tc`**: TC `clsact` **ingress**. GRO-safe; prefer this when native XDP is unavailable and generic XDP would otherwise miss multi-buffer packets (e.g. VLAN/bond).

> Prefer `tc` over `xdp-skb` when native XDP is not available: generic XDP only sees the first segment of GRO-aggregated packets. TC runs after GRO and reads the full skb.

### Agent metrics bind address

| `HUGINN_EBPF_METRICS_ADDR` | Listens on | Scrape / curl from |
| --- | --- | --- |
| **`127.0.0.1`** | Loopback in the agent netns only | Same netns, or host `127.0.0.1:$PORT` when the port is published. |
| **`0.0.0.0`** | All interfaces in that netns | Host or pod **IP** (+ port) when scraping **remotely** (not `127.0.0.1` from another machine). |

## Docker Compose specifics

- **`network_mode: "service:proxy"`** on the agent puts the agent in the **proxy’s network namespace**, so the interface name (`eth0`) and destination filter match the traffic the proxy actually receives.
- **`bpffs`** must be mounted into **both** containers at `/sys/fs/bpf` (or adjust paths consistently).
- **Health:** agent `/ready` should succeed when maps are pinned; proxy `/health` on `telemetry.metrics_port` is separate.

See [Containers](/huginn-proxy/docs/containers/) for the two Compose layouts (eBPF vs plain) and [Artifacts](/huginn-proxy/docs/artifacts/) for GHCR image names.

## Kubernetes networking

The SYN map is keyed by **source IP and port** as seen on the wire. CNIs that SNAT client traffic in a way that hides the original tuple can break correlation. Prefer CNIs that preserve the client endpoint toward the pod, or place the proxy where it sees the real tuple.

## Runtime lifecycle

- **Startup:** the proxy retries opening pinned maps until the agent has pinned them (start order does not matter).
- **Agent crash:** the proxy does **not** crash; lookups miss and `x-tcp-p0f` is simply omitted. Fresh captures stop until a healthy agent is attached again.
- **Agent restart:** pins are left in place and reused, so there is normally **no** reconnection gap. Maps are only recreated when `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` changes (or bpffs is wiped); then the proxy’s reconnect watcher adopts the new maps within `HUGINN_EBPF_RECONNECT_POLL_SECS`.
