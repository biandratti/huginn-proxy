---
title: Getting started
description: What Huginn Proxy is and where to go next.
sidebar:
  order: 1
---

Huginn Proxy is a reverse proxy built on [Tokio](https://tokio.rs), [Hyper](https://hyper.rs), and [Rustls](https://github.com/rustls/rustls). It passively fingerprints clients (TLS JA4, HTTP/2 Akamai, optional TCP SYN via eBPF) and injects trusted `x-tls-*`, `x-http2-*`, and `x-tcp-*` headers for backends. Fingerprinting primitives come from [Huginn Net](https://github.com/biandratti/huginn-net). TCP SYN fingerprinting is implemented via an eBPF program (XDP or TC) using [Aya](https://aya-rs.dev).

Inspired by production-grade proxies like [Pingora](https://github.com/cloudflare/pingora), and [rust-rpxy](https://github.com/junkurihara/rust-rpxy).

## Prerequisites

- Obtain a binary or image: use the [**latest releases**](https://github.com/biandratti/huginn-proxy/releases) on GitHub; see [Artifacts](/huginn-proxy/docs/artifacts/) for GHCR image names and [Containers](/huginn-proxy/docs/containers/) to run with Docker Compose.
- Linux (kernel ≥ 5.11) is required for TCP SYN / eBPF fingerprinting; TLS and HTTP/2 fingerprints work on other platforms when eBPF is disabled.

## Scope and limitations

Huginn Proxy is built for **passive fingerprinting** and a small set of production hardening features, not feature parity with general-purpose load balancers. Before you invest time, be aware of the rough edges (this list will grow as we document more):

- **TLS (per-domain certificates):** each `[[domains]]` entry carries its own `cert_path` / `key_path`. SNI-based certificate selection across domains is supported; the catch-all domain (no `host`) acts as the default certificate for unmatched-SNI or no-SNI connections.
- **TLS (certificate management):** there is **no built-in ACME** (Let's Encrypt), internal CA, or automatic issuance; many other proxies integrate that. You point config at files that **some other process** issues and renews (Kubernetes cert-manager, systemd timers, acme.sh, Vault, manual installs, etc.). Cert PEMs are re-read on **config reload** (SIGHUP or config-file watch), not by watching the cert files alone. See [TLS certificate rotation](/huginn-proxy/docs/tls/#certificate-rotation).
- **Load balancing:** simple **round-robin** when a route references more than one backend address. There are **no** in-proxy health checks, least-connections, or weights. The design assumes an **orchestrator** (Kubernetes, Nomad, Docker Compose, etc.) or another layer owns **replicas, health, and failover**. If you run bare VMs without that, plan for health and failover **outside** this proxy (see [Routes](/huginn-proxy/docs/routes/) for the longer story).

It is the current **scope**. If you **need an additional feature** (TLS, routing, balancing, ops, etc.), open an [**issue on GitHub**](https://github.com/biandratti/huginn-proxy/issues/new) and describe the **requirements and constraints** (environment, scale, must-haves vs nice-to-haves). That gives maintainers something concrete to evaluate; there is no guarantee of priority or implementation.