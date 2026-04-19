---
title: Docker Compose
description: Run Huginn Proxy with Docker Compose using pre-built GHCR images or local builds. Beta.
sidebar:
  order: 30
---

A one-off **`docker run` only for the proxy** is a poor fit for production: it omits TLS mounts, the **eBPF agent**, **bpffs**, and the **shared network namespace** the agent needs to attach XDP next to the proxy listener.

Image names and tags are documented in [Artifacts](/huginn-proxy/docs/artifacts/).

## Pre-built images (GHCR)

Canonical Compose files under [`examples/`](https://github.com/biandratti/huginn-proxy/tree/master/examples):

| File | Use |
| --- | --- |
| [`docker-compose.release-ebpf.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.release-ebpf.yml) | **Proxy + eBPF agent** — TCP SYN fingerprinting; Linux, `CAP_BPF`, bpffs volume |
| [`docker-compose.release.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.release.yml) | **Plain** proxy only — images from `huginn-proxy-plain`; no agent |

Pin versions by replacing `:latest` with `:vX.Y.Z` on **all** `huginn-proxy*` images so proxy and agent stay in sync.

**TLS and config paths:** the release Compose files mount `./config/compose.toml` (or **`compose.yaml`** if you use YAML) and **`./certs`** into the proxy container (`/config/certs` read-only). Create `examples/certs/` on the host with the certificate and key expected by your config (see the [`examples/` README](https://github.com/biandratti/huginn-proxy/tree/master/examples)); files must be readable by the container user (UID **10001**).

```bash
git clone https://github.com/biandratti/huginn-proxy.git
cd huginn-proxy/examples
# Generate or copy TLS material under ./certs per examples/README, then:
docker compose -f docker-compose.release-ebpf.yml pull
docker compose -f docker-compose.release-ebpf.yml up -d
```

For plain (no eBPF):

```bash
docker compose -f docker-compose.release.yml pull
docker compose -f docker-compose.release.yml up -d
```

## Build from source (same layout)

| File | Use |
| --- | --- |
| [`docker-compose.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.yml) | Proxy + eBPF agent + sample backends (build from repo) |
| [`docker-compose.plain.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.plain.yml) | Plain proxy only |

Run from a **clone** so paths like `examples/backend` resolve. The **README** in `examples/` has TLS generation, `curl` checks, and exact commands.

## eBPF wiring (must match)

Details: [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/).

- **Agent** uses `network_mode: "service:proxy"` so XDP sees the same `eth0` as the proxy listener.
- **`bpffs`** volume at `/sys/fs/bpf` in **both** agent and proxy; **`HUGINN_EBPF_PIN_PATH`** must match (e.g. `/sys/fs/bpf/huginn`).
- **Capabilities:** agent needs `BPF`, `NET_ADMIN`, `PERFMON` (and often relaxed seccomp); proxy typically needs `CAP_BPF` to open pinned maps.

## Production checklist (short)

- TLS material rotation and `watch` delay
- Resource limits and connection caps (`security.max_connections`)
- Scraping both proxy and agent metrics when eBPF is used

For Kubernetes, see [Kubernetes](/huginn-proxy/docs/kubernetes/).
