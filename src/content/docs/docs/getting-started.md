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

Huginn Proxy focuses on **passive fingerprinting** and a small set of hardening features, not feature parity with Nginx/Traefik. Current rough edges:

- **No built-in ACME:** certificates are files on disk (`cert_path` / `key_path` per domain). Another process issues and renews them (cert-manager, acme.sh, Vault, etc.). PEMs reload on **config reload**, not by watching cert files alone. See [TLS](/huginn-proxy/docs/tls/).
- **Load balancing:** round-robin across backend addresses on a route. Optional active [`health_check`](/huginn-proxy/docs/backends/#health-checks). No least-connections or weights; many setups still leave replicas and failover to an orchestrator (see [Routes](/huginn-proxy/docs/routes/)).

If you **need an additional feature**, open an [**issue on GitHub**](https://github.com/biandratti/huginn-proxy/issues/new) with requirements and constraints.
