<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Proxy Logo" width="200"/>

# Huginn Proxy

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-proxy#license)
[![Release](https://github.com/biandratti/huginn-proxy/actions/workflows/release.yml/badge.svg)](https://github.com/biandratti/huginn-proxy/actions/workflows/release.yml)
[![CI](https://github.com/biandratti/huginn-proxy/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/biandratti/huginn-proxy/actions/workflows/ci.yml)
[![Security](https://github.com/biandratti/huginn-proxy/actions/workflows/security.yml/badge.svg?branch=master)](https://github.com/biandratti/huginn-proxy/actions/workflows/security.yml)
[![Audit](https://github.com/biandratti/huginn-proxy/actions/workflows/audit.yml/badge.svg?branch=master)](https://github.com/biandratti/huginn-proxy/actions/workflows/audit.yml)
[![Pure Rust](https://img.shields.io/badge/pure-Rust-brightgreen.svg)](https://deps.rs/repo/github/biandratti/huginn-proxy)
[![codecov](https://codecov.io/gh/biandratti/huginn-proxy/graph/badge.svg)](https://codecov.io/gh/biandratti/huginn-proxy)
[![GitHub Release](https://img.shields.io/github/v/release/biandratti/huginn-proxy)](https://github.com/biandratti/huginn-proxy/releases)
[![GHCR packages](https://img.shields.io/badge/GHCR-container%20images-blue?logo=docker)](https://github.com/biandratti?tab=packages&repo_name=huginn-proxy)

**`ghcr.io/biandratti/`** — `huginn-proxy`, `huginn-proxy-plain`, `huginn-proxy-ebpf-agent` ([images & layout](#architecture))

**High-performance reverse proxy with passive fingerprinting capabilities powered by Huginn Net.**
</div>

## Overview

**Huginn Proxy** is a reverse proxy built on [Tokio](https://tokio.rs), [Hyper](https://hyper.rs), and [Rustls](https://github.com/rustls/rustls). It routes incoming connections to backend services while passively extracting TLS (JA4), HTTP/2 (Akamai), and TCP SYN (p0f-style) fingerprints and injecting them as headers. TCP SYN fingerprinting is implemented via an XDP eBPF program using [Aya](https://aya-rs.dev). Fingerprinting libraries are provided by [Huginn Net](https://github.com/biandratti/huginn-net).

Inspired by production-grade proxies
like [Pingora](https://github.com/cloudflare/pingora), [Sozu](https://github.com/sozu-proxy/sozu),
and [rust-rpxy](https://github.com/junkurihara/rust-rpxy).

## Quick Start

See [`examples/`](examples/).

## Features

- **Configuration** - One file, **[TOML or YAML](SETTINGS.md)** (picked from the extension). **Dynamic** sections (routes,
  backends, pools, headers, security filters, rate limits, …) **hot-reload** on SIGHUP or `--watch`; **static** sections
  (listen, TLS, fingerprint flags, logging, telemetry, timeouts, …) need a **restart** (reload ignores them). See
  [DEPLOYMENT.md](DEPLOYMENT.md).
- **IPv4 & IPv6 Dual-Stack** - Listen on both address families simultaneously with per-family eBPF maps
- **HTTP/1.x & HTTP/2** - Full support for both protocol versions
- **Load Balancing** - Round-robin load balancing across multiple backends
- **Connection Pooling** - Automatic connection reuse to backends for reduced latency (bypasses pooling per-route for
  fingerprinting)
- **Path-based Routing** - Route matching with prefix support, path stripping, and path rewriting
- **Rate Limiting** - Token bucket algorithm with multiple strategies (IP, Header, Route, Combined), global and
  per-route limits
- **Header Manipulation** - Add or remove request/response headers globally or per-route for security and customization
- **Security Headers** - HSTS, CSP, X-Frame-Options, and custom headers
- **IP Filtering (ACL)** - Allowlist/denylist with CIDR notation support
- **TLS Termination** - Server-side TLS with ALPN, certificate hot reload (single certificate per configuration)
- **TLS Session Resumption** - Support for TLS 1.2 session IDs and TLS 1.3 session tickets
- **mTLS (Mutual TLS)** - Client certificate authentication for secure service-to-service communication
- **Granular Timeouts** - TLS handshake and connection handling timeouts for resource protection
- **Host Header Preservation** - Configurable forwarding of original Host header for virtual hosting
- **Passive Fingerprinting** - Automatic TLS (JA4), HTTP/2 (Akamai), and TCP SYN (p0f-style via eBPF) fingerprint extraction
- **X-Forwarded-* Headers** - Automatic injection of proxy forwarding headers
- **[Comprehensive Telemetry](TELEMETRY.md)** - Prometheus metrics covering requests, throughput, rate limiting, TLS,
  backends, and security features
- **High Performance** - Built on Tokio and Hyper
- **Easy Deployment** - Single binary, Docker-ready

See [FEATURES.md](FEATURES.md) for detailed descriptions and limitations of each feature.
See [SETTINGS.md](SETTINGS.md) for the full configuration reference (TOML and YAML).

For deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

## Fingerprinting

Fingerprints are automatically extracted and injected as headers:

- **TLS (JA4)**: `x-huginn-net-ja4`: sorted cipher suites and extensions, SHA-256 hashed. Standard FoxIO JA4.
  using [huginn-net-tls](https://crates.io/crates/huginn-net-tls)
- **TLS (JA4_r)**: `x-huginn-net-ja4_r`: original ClientHello order, SHA-256 hashed (FoxIO JA4_r)
- **TLS (JA4_o)**: `x-huginn-net-ja4_o`: sorted, raw hex values without hashing (FoxIO JA4_o, useful for debugging)
- **TLS (JA4_or)**: `x-huginn-net-ja4_or`: original order, raw hex values without hashing (FoxIO JA4_or)
- **HTTP/2 (Akamai)**: `x-huginn-net-akamai`: Extracted from HTTP/2 connections only using [huginn-net-http](https://crates.io/crates/huginn-net-http)
- **TCP SYN (p0f-style)**: `x-huginn-net-tcp` - Raw TCP SYN signature extracted via eBPF/XDP
  using [huginn-net-tcp](https://crates.io/crates/huginn-net-tcp). Requires `tcp_enabled = true`
  and the `ebpf-tcp` feature. Present on all requests of a connection (the fingerprint is
  captured once at TCP accept time and reused). IPv4 and IPv6 SYNs are captured when the next
  header after the fixed IPv6 header is TCP (see [FEATURES.md](FEATURES.md)).
  See [EBPF-SETUP.md](EBPF-SETUP.md) for setup, kernel requirements, and deployment options.
- The proxy automatically injects standard `X-Forwarded-*` headers to inform backends about the original client request:

**Examples:**

```
x-huginn-net-ja4:    t13d3112h2_e8f1e7e78f70_b26ce05bbdd6,
x-huginn-net-ja4_r:  t13d3112h2_002f,0033,0035,0039,003c,003d,0067,006b,009c,009d,009e,009f,00ff,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9,ccaa_000a,000b,000d,0015,0016,0017,002b,002d,0031,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602,
x-huginn-net-ja4_o:  t13d3112h2_d7c3e2abb617_cad92ccb4254,
x-huginn-net-ja4_or: t13d3112h2_1302,1303,1301,c02c,c030,009f,cca9,cca8,ccaa,c02b,c02f,009e,c024,c028,006b,c023,c027,0067,c00a,c014,0039,c009,c013,0033,009d,009c,003d,003c,0035,002f,00ff_0000,000b,000a,0010,0016,0017,0031,000d,002b,002d,0033,0015_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602,
x-huginn-net-ja4_r:  t13d3112h2_d7c3e2abb617_cad92ccb4254,
x-huginn-net-akamai: 3:100;4:10485760;2:0|1048510465|0|m,s,a,p,
x-huginn-net-tcp:    4:64+0:0:1460:mss*44,10:mss,sok,ts,nop,ws:df,id+:0,
x-forwarded-for:     172.18.0.1,
x-forwarded-port:    50908,
x-forwarded-proto:   https,
x-forwarded-host:    localhost
```

These headers always override any client-provided values to prevent spoofing.

## Performance

- **Fingerprinting Overhead**: ~2.2% (minimal impact)
- **Concurrent Connections**: Handles thousands of concurrent connections
- **Latency**: Sub-millisecond overhead for fingerprint extraction

See [`benches/README.md`](benches/README.md) for detailed benchmark results from development environment.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for a detailed list of planned features and upcoming phases.

## Deployment matrix

Published images (`linux/amd64`, `linux/arm64`), release binaries, and capabilities: **[DEPLOYMENT-MATRIX.md](DEPLOYMENT-MATRIX.md)**. See also [DEPLOYMENT.md](DEPLOYMENT.md) and [EBPF-SETUP.md](EBPF-SETUP.md); local Compose under [`examples/`](examples/).

## Architecture

For module structure and design decisions, see [ARCHITECTURE.md](ARCHITECTURE.md).

| Fingerprint | Header | eBPF agent required                 |
|---|---|-------------------------------------|
| TLS (JA4) | `x-huginn-net-ja4` | No                                  |
| HTTP/2 (Akamai) | `x-huginn-net-akamai` | No                                  |
| TCP SYN (p0f) | `x-huginn-net-tcp` | **Yes** - Linux only, kernel ≥ 5.11 |

**GHCR:** three container packages ([`huginn-proxy`](https://github.com/biandratti/huginn-proxy/pkgs/container/huginn-proxy), [`huginn-proxy-plain`](https://github.com/biandratti/huginn-proxy/pkgs/container/huginn-proxy-plain), [`huginn-proxy-ebpf-agent`](https://github.com/biandratti/huginn-proxy-ebpf-agent/pkgs/container/huginn-proxy-ebpf-agent)). How many you run depends on the setup:

- **Proxy + eBPF agent (TCP SYN):** **`huginn-proxy`** + **`huginn-proxy-ebpf-agent`** two containers; JA4, Akamai, and `x-huginn-net-tcp`.
- **Proxy only (no TCP SYN):** **`huginn-proxy-plain`** one container; JA4 and Akamai, no kernel SYN path.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).

### Attribution

Huginn Proxy uses the [Huginn Net](https://github.com/biandratti/huginn-net) fingerprinting libraries:

- **JA4**: TLS fingerprinting follows the [JA4 specification by FoxIO, LLC](https://github.com/FoxIO-LLC/ja4)
- **Akamai HTTP/2**: HTTP/2 fingerprinting follows
  the [Blackhat EU 2017 specification](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)
- **p0f v3**: TCP SYN fingerprinting follows the [p0f v3 specification by Michal Zalewski](https://lcamtuf.coredump.cx/p0f3/README)

## Contributing

Contributions are welcome! Please see our contributing guidelines for details.
