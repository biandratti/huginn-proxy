---
title: Fingerprinting
description: TLS JA4, HTTP/2 Akamai-style, and TCP SYN headers. Beta.
sidebar:
  order: 4
---

Huginn Proxy passively extracts fingerprints and forwards them as request headers. Analysis and blocking decisions belong on the backend.

## TLS (JA4 family)

Derived from the TLS ClientHello (via [huginn-net-tls](https://crates.io/crates/huginn-net-tls)):

| Header | Role |
| --- | --- |
| `x-huginn-net-ja4` | Sorted cipher suites and extensions, SHA-256 hashed (FoxIO JA4) |
| `x-huginn-net-ja4_r` | Original ClientHello order, hashed (JA4_r) |
| `x-huginn-net-ja4_o` | Sorted, raw hex (JA4_o), useful for debugging |
| `x-huginn-net-ja4_or` | Original order, raw hex (JA4_or) |

TLS fingerprints are usually **once per TLS session**. For debugging per-connection variation (e.g. extension order randomization), you may need to force new connections or adjust ALPN / keep-alive. That is not generally recommended for production.

## HTTP/2 (Akamai-style)

On HTTP/2 connections only, a compact signature is emitted as `x-huginn-net-akamai` using [huginn-net-http](https://crates.io/crates/huginn-net-http).

## TCP SYN (p0f-style, optional)

When built with `ebpf-tcp`, `tcp_enabled = true`, and the [eBPF agent](/huginn-proxy/docs/ebpf-setup/) is running, a p0f-style string is sent as `x-huginn-net-tcp` ([huginn-net-tcp](https://crates.io/crates/huginn-net-tcp)).

**Constraints**

- Linux with XDP/eBPF; not available on macOS or Windows for this path.
- Typically **one signature per TCP connection**, reused across HTTP requests on that connection.

## Per-route toggle

`fingerprinting` on a route can disable TLS and HTTP/2 fingerprint injection for that route. TCP SYN remains governed by the global `fingerprint.tcp_enabled` flag.
