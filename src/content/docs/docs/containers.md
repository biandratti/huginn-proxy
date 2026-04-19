---
title: Containers
description: Two Docker Compose layouts — full eBPF TCP SYN + TLS + HTTP fingerprints, or TLS + HTTP only. Beta.
sidebar:
  order: 30
---

Huginn Proxy is published as **container images**; how you compose them matters. There are **two different setups**:

1. **Full fingerprint path** — **TCP SYN** (eBPF sidecar) plus **TLS (JA4)** and **HTTP/2 (Akamai)** inside the proxy. Extra containers, kernel, and privileges.
2. **TLS + HTTP only** — **JA4** and **Akamai** still come from the proxy; the **TCP SYN** path (`x-huginn-net-tcp`) is **not** available without the eBPF stack.

Do not mix them blindly: the Compose files, images, and mounts are **not** drop-in replacements for each other.

Image names and tags: [Artifacts](/huginn-proxy/docs/artifacts/). Config samples live under [`examples/config/`](https://github.com/biandratti/huginn-proxy/tree/master/examples/config) (`compose.toml` / `compose.yaml`).

## TLS certificates on the host

The Compose examples mount **`./certs`** from `examples/` into the proxy at **`/config/certs`** (read-only). Paths and filenames must match what your config references (the samples expect PEM material such as **`server.crt`** and **`server.key`** under that mount).

Do **not** duplicate certificate recipes here — they drift easily. Follow **[`examples/README.md`](https://github.com/biandratti/huginn-proxy/blob/master/examples/README.md)** on GitHub: create `examples/certs/`, generate certs (OpenSSL self-signed or `mkcert`), permissions, and smoke tests (`curl`, browser). Files should be readable by the container user where the image documents one (often UID **10001**).

---

## Full stack: TCP SYN + TLS + HTTP fingerprints

**What you get**

| Layer | Where it runs | Notes |
| --- | --- | --- |
| **TLS JA4** | Proxy process | From the client→proxy TLS handshake. |
| **HTTP/2 Akamai** | Proxy process | On HTTP/2 connections. |
| **TCP SYN (p0f-style)** | **eBPF agent** container + XDP | Requires Linux (e.g. kernel ≥ 5.11), `bpffs`, pinned maps, and caps — see [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/). |

**Compose layout**

- **`proxy`:** image `ghcr.io/biandratti/huginn-proxy:latest` (full binary, not the `plain` variant).
- **`ebpf-agent`:** image `ghcr.io/biandratti/huginn-proxy-ebpf-agent:latest`, `network_mode: "service:proxy"` so XDP attaches next to the proxy listener.
- **`bpffs`** volume mounted in **both** agent and proxy; **`HUGINN_EBPF_PIN_PATH`** must match (e.g. `/sys/fs/bpf/huginn`).
- **Backends** in the example are sample upstreams (e.g. `traefik/whoami`).

**Reference file (pre-built GHCR images):** [`examples/docker-compose.release-ebpf.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.release-ebpf.yml)

The proxy command passes the config file (e.g. `/config/compose.toml`); ensure **`fingerprint.tcp_enabled`** and the rest of the stack match what this layout provides.

```bash
git clone https://github.com/biandratti/huginn-proxy.git
cd huginn-proxy/examples
# Certs + config: see examples/README.md (TLS section), then:
docker compose -f docker-compose.release-ebpf.yml pull
docker compose -f docker-compose.release-ebpf.yml up -d
```

Pin **`:latest`** to **`:vX.Y.Z`** on **all** `huginn-proxy*` images from the same release.

---

## TLS + HTTP fingerprints only (no TCP SYN)

**What you get**

- **TLS JA4** and **HTTP/2 Akamai** — same as in the full stack, as long as `[fingerprint]` and routes allow it.
- **No TCP SYN header** — no eBPF agent, no XDP, no `bpffs` for this path.

**Compose layout**

- **Single `proxy` service** (plus backends in the example). **No** `ebpf-agent` service.
- **Pre-built GHCR images:** image `ghcr.io/biandratti/huginn-proxy-plain:latest` — no local Docker build required.

**Reference file (pull from registry):** [`examples/docker-compose.release.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.release.yml)

It mounts config and certs like the eBPF release file; set `HUGINN_CONFIG_PATH` / volumes to match **`compose.toml`** or **`compose.yaml`** as you prefer.

```bash
git clone https://github.com/biandratti/huginn-proxy.git
cd huginn-proxy/examples
# Certs + config: see examples/README.md (TLS section), then:
docker compose -f docker-compose.release.yml pull
docker compose -f docker-compose.release.yml up -d
```

**Build from source instead:** to compile the **`plain`** image locally (no GHCR pull), use [`docker-compose.plain.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.plain.yml) — `docker compose -f docker-compose.plain.yml up -d --build`. Same fingerprint model (JA4 + Akamai, no TCP SYN), different delivery path.

---

## Production checklist (short)

- TLS rotation and watch delay when using file-based certs.
- Resource limits and `security.max_connections`.
- With eBPF: scrape **proxy** metrics (e.g. `:9090`) and **agent** metrics (e.g. `:9091`) as in the Compose files.

For Kubernetes, see [Kubernetes](/huginn-proxy/docs/kubernetes/).
