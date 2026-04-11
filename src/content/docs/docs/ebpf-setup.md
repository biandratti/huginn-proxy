---
title: eBPF TCP setup
description: XDP agent, pinned maps, and kernel requirements for TCP SYN fingerprints. Beta.
sidebar:
  order: 32
---

TCP SYN fingerprinting uses an **XDP** program loaded by **`huginn-ebpf-agent`**. The agent pins BPF maps under **bpffs** (for example under `HUGINN_EBPF_PIN_PATH`). **Huginn Proxy** opens those maps read-only and emits `x-huginn-net-tcp`.

## Architecture

Two processes cooperate:

1. **eBPF agent** (`huginn-ebpf-agent`): loads XDP, attaches to the interface, pins maps, exposes metrics, stays running.
2. **Proxy** (`huginn-proxy`): accepts connections, looks up `(src_ip, src_port)` in the map, formats the p0f-style signature.

## Preconditions

- **Kernel ≥ 5.11** (recommended for current BPF UAPI).
- **bpffs** mounted at `/sys/fs/bpf` (Compose uses a `bpf` volume; on bare metal ensure the mount exists).
- **One agent per interface** that loads XDP on that NIC; two loaders on the same interface race.

## Capabilities

| Component | Typical needs |
| --- | --- |
| **eBPF agent** | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` (or root); often **seccomp/apparmor unconfined** so `bpf()` and XDP attach succeed in containers. |
| **Proxy** | **`CAP_BPF`** is enough when it only **opens** pinned maps (no XDP load in the proxy process). |

## Environment variables

These must be **consistent** between agent and proxy where shared (pin path, map size). Names match what the binaries read at runtime.

| Variable | Role |
| --- | --- |
| `HUGINN_EBPF_PIN_PATH` | Directory under bpffs where maps are pinned (e.g. `/sys/fs/bpf/huginn`). **Same** on agent and proxy. |
| `HUGINN_EBPF_INTERFACE` | NIC the agent attaches XDP to (in Docker Compose with `network_mode: service:proxy`, this is the **proxy** container’s `eth0`). |
| `HUGINN_EBPF_DST_PORT` | Listener port the agent filters toward (the proxy’s TLS/HTTP port, e.g. `7000`). |
| `HUGINN_EBPF_DST_IP_V4` | IPv4 address considered “to the proxy” (`0.0.0.0` often means any local IPv4 listener on that port; align with your bind addresses). |
| `HUGINN_EBPF_DST_IP_V6` | IPv6 counterpart (e.g. `::` for any). |
| `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` | BPF map capacity for SYN entries; **same** on agent and proxy. |
| `HUGINN_EBPF_XDP_MODE` | XDP attach mode (e.g. `skb` vs `native` / driver-dependent; see agent docs in repo). |
| `HUGINN_EBPF_METRICS_ADDR` / `HUGINN_EBPF_METRICS_PORT` | Where the **agent** binds its HTTP health/metrics (often `127.0.0.1` inside the proxy netns; publish `9091` on the proxy service if you scrape from the host). |

Full stack layout (Compose, caps, volumes) is maintained in [`examples/docker-compose.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.yml); **do not treat this table as a second source of truth** if the repo changes defaults.

## Docker Compose specifics

- **`network_mode: "service:proxy"`** on the agent puts the agent in the **proxy’s network namespace**, so the interface name (`eth0`) and destination filter match the traffic the proxy actually receives.
- **`bpffs`** must be mounted into **both** containers at `/sys/fs/bpf` (or adjust paths consistently).
- **Health:** agent `/ready` should succeed when maps are pinned; proxy `/health` on `telemetry.metrics_port` is separate.

See [Docker Compose](/huginn-proxy/docs/deployment/) for the Compose file index and clone/run flow, and [Artifacts](/huginn-proxy/docs/artifacts/) for GHCR image names.

## Kubernetes networking

The SYN map is keyed by **source IP and port** as seen on the wire. CNIs that SNAT client traffic in a way that hides the original tuple can break correlation. Prefer CNIs that preserve the client endpoint toward the pod, or place the proxy where it sees the real tuple.

## Ordering

Start the **agent before** or restart the proxy after maps exist; the proxy retries map open when the agent comes up later.
