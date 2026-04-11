---
title: Artifacts
description: Published container images on GHCR and release binaries. Beta.
sidebar:
  order: 29
---

Published **container images** (GHCR) and **release binaries**: tags, platforms, and when eBPF applies.

Quick local setup: [`examples/`](https://github.com/biandratti/huginn-proxy/tree/master/examples) on the `master` branch. Deployment topics: [Docker Compose](/huginn-proxy/docs/deployment/), [Kubernetes](/huginn-proxy/docs/kubernetes/).

## Docker images

Runtime images are published for `linux/amd64` and `linux/arm64`. There are **three separate GHCR packages**; each uses the same tags (`latest` and `vX.Y.Z` from [GitHub Releases](https://github.com/biandratti/huginn-proxy/releases)). Pin the **same version** on proxy and agent when using TCP SYN fingerprinting.

| Image | Base | User | Capabilities |
| --- | --- | --- | --- |
| `ghcr.io/biandratti/huginn-proxy:latest` | `debian:trixie-slim` (Debian 13) | `10001` | Proxy (eBPF build) — reads pinned maps — `CAP_BPF` |
| `ghcr.io/biandratti/huginn-proxy-plain:latest` | `debian:trixie-slim` (Debian 13) | `10001` | Proxy without eBPF in the binary |
| `ghcr.io/biandratti/huginn-proxy-ebpf-agent:latest` | `debian:trixie-slim` (Debian 13) | `root` | Agent loads XDP — `CAP_BPF` `CAP_NET_ADMIN` `CAP_PERFMON` |

Replace `:latest` with `:vX.Y.Z` to pin a release.

## Release binaries

| Artifact | Suffix | OS | Arch | libc | eBPF |
| --- | --- | --- | --- | --- | --- |
| `huginn-proxy` | `x86_64-unknown-linux-musl` | Linux | amd64 | musl (static) | No |
| `huginn-proxy` | `aarch64-unknown-linux-musl` | Linux | arm64 | musl (static) | No |
| `huginn-proxy` | `x86_64-unknown-linux-gnu-ebpf` | Linux | amd64 | glibc | Yes (reader) |
| `huginn-proxy` | `aarch64-unknown-linux-gnu-ebpf` | Linux | arm64 | glibc | Yes (reader) |
| `huginn-proxy` | `x86_64-apple-darwin` | macOS | amd64 | — | No |
| `huginn-proxy` | `aarch64-apple-darwin` | macOS | arm64 | — | No |
| `huginn-ebpf-agent` | `x86_64-unknown-linux-gnu-ebpf-agent` | Linux | amd64 | glibc | Yes (loader) |
| `huginn-ebpf-agent` | `aarch64-unknown-linux-gnu-ebpf-agent` | Linux | arm64 | glibc | Yes (loader) |

- **musl (static):** zero runtime dependencies; runs on any Linux kernel and distro (no TCP SYN via eBPF in this build).
- **glibc (eBPF):** Linux binaries extracted from or aligned with the Docker images; TCP SYN path needs kernel ≥ 5.11 and the agent where applicable.

## Where to download

- **[GitHub Releases](https://github.com/biandratti/huginn-proxy/releases)** — attached files on each tag.
- **Actions** — workflow **Release** for that tag → **Artifacts** (ZIP per platform).

Images stay on **GHCR**; they are not attached as files on the Releases page.
