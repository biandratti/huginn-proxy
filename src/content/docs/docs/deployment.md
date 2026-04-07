---
title: Deployment
description: Docker, Compose, and Kubernetes patterns. Beta.
sidebar:
  order: 30
---

## Container image

Publish workflow and tags are defined on `master` in the GitHub repository. Run the binary as:

```bash
docker run -d \
  --name huginn-proxy \
  -p 7000:7000 -p 9090:9090 \
  -v $(pwd)/config.toml:/config/config.toml:ro \
  ghcr.io/biandratti/huginn-proxy:latest \
  /usr/local/bin/huginn-proxy /config/config.toml
```

Mount TLS material read-only when `[tls]` is enabled. Container images run the workload user with a fixed UID; ensure cert files are readable by that user.

## Docker Compose

The repository ships Compose manifests under `examples/` on `master`:

- Full stack with eBPF agent, proxy, backends, and health checks
- **Plain** variant without TCP SYN fingerprinting for simpler hosts

Typical flow:

```bash
cd examples
docker compose up -d
```

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
