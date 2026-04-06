---
title: eBPF TCP setup
description: XDP agent, pinned maps, and kernel requirements for TCP SYN fingerprints. Beta.
sidebar:
  order: 31
---

TCP SYN fingerprinting uses an **XDP** program loaded by **`huginn-ebpf-agent`**. The agent pins BPF maps under bpffs (for example `/sys/fs/bpf/huginn/`). **Huginn Proxy** opens those maps read-only and emits `x-huginn-net-tcp`.

## Architecture

Two processes cooperate:

1. **Agent:** loads XDP, attaches to the interface, pins maps, stays running.
2. **Proxy:** accepts connections, looks up `(src_ip, src_port)` in the map, formats the p0f-style signature.

## Preconditions

- **Kernel ≥ 5.11** recommended for modern BPF UAPI.
- **bpffs** mounted at `/sys/fs/bpf`.
- **One agent per interface:** two loaders race to attach XDP.
- For the documented XDP capture path, **IPv4** listen addresses align with how packets are selected; enabling IPv6-only listen with `tcp_enabled` may fail fast. See upstream `EBPF-SETUP.md` on `master`.

## Capabilities

The agent needs appropriate Linux capabilities (e.g. `BPF`, `NET_ADMIN`, often `PERFMON`) and, in many clusters, an unconfined seccomp profile for `bpf()` syscalls. The proxy **does not** need the same caps when it only opens pinned maps.

## Environment variables (typical)

Examples (exact names in source / docs on `master`):

- `HUGINN_EBPF_PIN_PATH`: where maps are pinned
- `HUGINN_EBPF_INTERFACE`: NIC to attach XDP
- `HUGINN_EBPF_DST_PORT` / `HUGINN_EBPF_DST_IP_V4`: filter traffic toward the proxy listener
- `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES`: map sizing
- `HUGINN_EBPF_METRICS_ADDR` / `HUGINN_EBPF_METRICS_PORT`: agent metrics bind

## Kubernetes networking

The SYN map is keyed by **source IP and port** as seen on the wire. CNIs that SNAT client traffic in a way that hides the original tuple can break correlation. Prefer CNIs that preserve the client endpoint toward the pod, or place the proxy where it sees the real tuple.

## Ordering

Start the **agent before** or restart the proxy after maps exist; the proxy retries map open when the agent comes up later.
