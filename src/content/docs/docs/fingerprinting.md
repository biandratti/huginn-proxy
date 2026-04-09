---
title: Fingerprinting
description: TLS JA4, HTTP/2 Akamai, and TCP SYN headers. Beta.
sidebar:
  order: 6
---

Huginn Proxy passively extracts fingerprints and forwards them as request headers. Analysis and blocking decisions belong on the backend.

For a full feature overview (protocols, limitations, metrics), see [Features](https://github.com/biandratti/huginn-proxy/blob/master/FEATURES.md) on GitHub.

Global toggles live under **`[fingerprint]`**. Per-route control uses **`fingerprinting`** on each route (TLS + HTTP/2 only; TCP SYN stays global).

## TLS [JA4]

Derived from the TLS ClientHello (via [huginn-net-tls](https://crates.io/crates/huginn-net-tls)):

| Header | Role |
| --- | --- |
| `x-huginn-net-ja4` | Sorted cipher suites and extensions, SHA-256 hashed (FoxIO JA4) |
| `x-huginn-net-ja4_r` | Original ClientHello order, hashed (JA4_r) |
| `x-huginn-net-ja4_o` | Sorted, raw hex (JA4_o), useful for debugging |
| `x-huginn-net-ja4_or` | Original order, raw hex (JA4_or) |

TLS fingerprints are usually **once per TLS session**. For debugging per-connection variation (e.g. extension order randomization), you may need to force new connections or adjust ALPN / keep-alive. That is not generally recommended for production.

**Enable or disable globally** with `tls_enabled`:

```toml
[fingerprint]
tls_enabled = true   # default: inject JA4 headers when TLS is used
# tls_enabled = false  # no TLS fingerprint headers on any route
```

**Per route:** use `fingerprinting` on the route (see [Per-route](#per-route-toggle)); it turns **TLS and HTTP/2** fingerprint headers on or off together for that prefix.

## HTTP/2 [Akamai]

On HTTP/2 connections only, a compact signature is emitted as `x-huginn-net-akamai` using [huginn-net-http](https://crates.io/crates/huginn-net-http).

**Enable or disable globally** with `http_enabled`:

```toml
[fingerprint]
http_enabled = true   # default: Akamai header on h2 when fingerprinting is on
# http_enabled = false  # no HTTP/2 fingerprint header on any route
```

If `tls_enabled` or `http_enabled` is `false`, the corresponding headers are not injected. Per-route `fingerprinting` applies to **both** TLS and HTTP/2 fingerprints for that route.

## TCP SYN [p0f]

When built with `ebpf-tcp`, `tcp_enabled = true`, and the [eBPF agent](/huginn-proxy/docs/ebpf-setup/) is running, a p0f-style string is sent as `x-huginn-net-tcp` ([huginn-net-tcp](https://crates.io/crates/huginn-net-tcp)).

**Enable or disable globally.** There is **no per-route** TCP SYN toggle:

```toml
[fingerprint]
tcp_enabled = true
# tcp_enabled = false   # no x-huginn-net-tcp; proxy still runs without eBPF TCP path
```

**Constraints**

- Linux with XDP/eBPF; not available on macOS or Windows for this path.
- Typically **one signature per TCP connection**, reused across HTTP requests on that connection.

## Per-route toggle

`fingerprinting` on a route enables or disables **TLS (JA4) and HTTP/2 (Akamai)** headers for requests matching that route. **TCP SYN** remains governed only by **`fingerprint.tcp_enabled`** (global).

Example: fingerprints on `/api`, but not on `/static`:

```toml
routes = [
    { prefix = "/api", backend = "api:9000", fingerprinting = true },
    { prefix = "/static", backend = "cdn:9000", fingerprinting = false },
]

[fingerprint]
tls_enabled = true
http_enabled = true
tcp_enabled = true   # still applies to all routes when eBPF is available
```

Example: disable TLS + HTTP/2 fingerprints everywhere via config, but keep the section for documentation:

```toml
[fingerprint]
tls_enabled = false
http_enabled = false
tcp_enabled = true   # only TCP SYN headers (if eBPF build + agent)
```

See [Configuration overview](/huginn-proxy/docs/configuration/) for where `[fingerprint]` sits in the file; fields include `max_capture` (HTTP/2 capture cap).
