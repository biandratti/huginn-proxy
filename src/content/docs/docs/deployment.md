---
title: Deployment
description: Docker, Compose, and Kubernetes patterns. Beta.
sidebar:
  order: 30
---

## Container images

Images are published to **`ghcr.io/biandratti/huginn-proxy`**: the **proxy**, **`-plain`** builds (no eBPF in the binary), and the **`-ebpf-agent`** sidecar. Pin an explicit **version tag** from [GitHub Releases](https://github.com/biandratti/huginn-proxy/releases) for both proxy and agent so they stay in sync.

A one-off **`docker run` only for `huginn-proxy`** is a poor fit: it omits TLS mounts, the **eBPF agent**, **bpffs**, and the **shared network namespace** the agent needs to attach XDP next to the proxy listener. Use the Compose files in the repository as the single source of truth (same idea as Traefik pointing at their tracked `docker-compose` rather than pasting a full copy in the docs site).

## Docker Compose

Canonical files live under [**examples**](https://github.com/biandratti/huginn-proxy/tree/master/examples):

| File | Use |
| --- | --- |
| [`docker-compose.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.yml) | Proxy + **eBPF agent** + sample backends (TCP SYN fingerprinting; Linux, extra caps) |
| [`docker-compose.plain.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.plain.yml) | **Plain** proxy only (no agent; simpler kernels / hosts) |

The **README** in that directory has TLS generation, image tags, `curl` checks, and the exact `docker compose` commands. Run from a **clone** so paths like `examples/backend` resolve.

```bash
git clone https://github.com/biandratti/huginn-proxy.git
cd huginn-proxy/examples
# see README: certs, then e.g.
docker compose -f docker-compose.yml up --build
```

**Wiring you must not get wrong** (details in [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/)):

- **Agent** uses `network_mode: "service:proxy"` so XDP sees the same `eth0` as the proxy listener.
- **`bpffs`** volume mounted at `/sys/fs/bpf` in **both** agent and proxy; **`HUGINN_EBPF_PIN_PATH`** must match (e.g. `/sys/fs/bpf/huginn`).
- **Capabilities:** agent needs `BPF`, `NET_ADMIN`, `PERFMON` (and often relaxed seccomp); proxy typically needs `CAP_BPF` to open pinned maps.

Mount TLS material **read-only** when `[tls]` is enabled. Images run as a fixed workload UID; certs on the host must be readable inside the container.

## Kubernetes

**Split responsibilities**

- **eBPF agent:** `DaemonSet`, one pod per node that needs SYN capture; `hostNetwork` is commonly required for XDP on the real NIC; elevated capabilities (`BPF`, `NET_ADMIN`, …) and `bpffs` mounts.
- **Proxy:** `Deployment` with replicas as needed; opens **pinned** BPF maps read-only when TCP SYN is enabled. It does not load XDP itself.

Pin paths and interface names must match between agent configuration and node networking. Readiness should probe the agent’s `/ready` endpoint when maps must be present before traffic.

See [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/) for environment variables and security context details.

## Production checklist (short)

- TLS material rotation and `watch` delay
- Resource limits and connection caps (`security.max_connections`)
- Scraping both proxy and agent metrics when eBPF is used
- CNI / source-address visibility for SYN correlation (avoid blind SNAT toward the proxy pod)
