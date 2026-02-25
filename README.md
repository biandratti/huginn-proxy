<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Proxy Logo" width="200"/>

# Huginn Proxy

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-proxy#license)
[![CI](https://github.com/biandratti/huginn-proxy/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/biandratti/huginn-proxy/actions/workflows/ci.yml)
[![Security](https://github.com/biandratti/huginn-proxy/actions/workflows/security.yml/badge.svg?branch=master)](https://github.com/biandratti/huginn-proxy/actions/workflows/security.yml)
[![Audit](https://github.com/biandratti/huginn-proxy/actions/workflows/audit.yml/badge.svg?branch=master)](https://github.com/biandratti/huginn-proxy/actions/workflows/audit.yml)
[![Pure Rust](https://img.shields.io/badge/pure-Rust-brightgreen.svg)](https://deps.rs/repo/github/biandratti/huginn-proxy)
[![codecov](https://codecov.io/gh/biandratti/huginn-proxy/graph/badge.svg)](https://codecov.io/gh/biandratti/huginn-proxy)

**High-performance reverse proxy with passive fingerprinting capabilities powered by Huginn Net.**
</div>

## Overview

**Huginn Proxy** is a reverse proxy built on [Tokio](https://tokio.rs), [Hyper](https://hyper.rs), and [Rustls](https://github.com/rustls/rustls). It routes incoming connections to backend services while passively extracting TLS (JA4), HTTP/2 (Akamai), and TCP SYN (p0f-style) fingerprints and injecting them as headers. TCP SYN fingerprinting is implemented via an XDP eBPF program using [Aya](https://aya-rs.dev). Fingerprinting libraries are provided by [Huginn Net](https://github.com/biandratti/huginn-net).

Inspired by production-grade proxies
like [Pingora](https://github.com/cloudflare/pingora), [Sozu](https://github.com/sozu-proxy/sozu),
and [rust-rpxy](https://github.com/junkurihara/rust-rpxy).

> **Note:** This project is currently in active development.

## Quick Start

See [`examples/`](examples/) for the full setup guide, including:

- Building from source (standard and with eBPF/TCP SYN fingerprinting)
- Generating TLS certificates
- Running with Docker Compose
- Configuration examples (rate limiting, routing, …)

## Features

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

For deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

For module structure and design decisions, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Fingerprinting

Fingerprints are automatically extracted and injected as headers:

- **TLS (JA4)**: `x-huginn-net-ja4` - Extracted from all TLS connections
  using [huginn-net-tls](https://crates.io/crates/huginn-net-tls)
- **TLS (JA4 Raw)**: `x-huginn-net-ja4-raw` - Raw/original JA4 fingerprint format
- **HTTP/2 (Akamai)**: `x-huginn-net-akamai` - Extracted from HTTP/2 connections only
  using [huginn-net-http](https://crates.io/crates/huginn-net-http)
- **TCP SYN (p0f-style)**: `x-huginn-net-tcp` - Raw TCP SYN signature extracted via eBPF/XDP
  using [huginn-net-tcp](https://crates.io/crates/huginn-net-tcp). Requires `tcp_enabled = true`
  and the `ebpf-tcp` feature. Present on all requests of a connection (the fingerprint is
  captured once at TCP accept time and reused). **IPv4 only** — not captured for direct IPv6
  connections (transparent when a load balancer forwards internally over IPv4).
  See [EBPF-SETUP.md](EBPF-SETUP.md) for setup, kernel requirements, and deployment options.

**Examples:**

```
x-huginn-net-ja4: t13d3112h2_e8f1e7e78f70_b26ce05bbdd6
x-huginn-net-ja4-raw: t13d3112h2_d7c3e2abb617_cad92ccb4254
x-huginn-net-akamai: 3:100;4:10485760;2:0|1048510465|0|
x-huginn-net-tcp: 4:64:0:1460:mss*44,10:mss,sok,ts,nop,ws
```

See [JA4 specification](https://github.com/FoxIO-LLC/ja4)
and [Blackhat EU 2017](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)
for details.

## Proxy Headers

The proxy automatically injects standard `X-Forwarded-*` headers to inform backends about the original client request:

- **X-Forwarded-For**: Client IP address (appended if already present)
- **X-Forwarded-Host**: Original Host header value
- **X-Forwarded-Port**: Client port number
- **X-Forwarded-Proto**: Protocol used (`http` or `https`)

These headers always override any client-provided values to prevent spoofing.

## Advanced Configuration Options

### Per-Route Settings

- **`fingerprinting`** (bool, default: `true`) - Enable/disable TLS (JA4) and HTTP/2 (Akamai) fingerprint extraction and
  header injection
- **`force_new_connection`** (bool, default: `false`) - Force new TCP + TLS handshake per request, bypassing connection
  pooling and HTTP keep-alive reuse
    - Use case: Per-request TLS fingerprinting, TCP SYN fingerprinting (each request generates a
      fresh SYN, so the eBPF map always has an entry), testing/debugging

## Health Check Endpoints

When `telemetry.metrics_port` is configured, Huginn Proxy exposes health check endpoints on the observability server (
separate from the main proxy port):

- **`/health`** - General health check (`200 OK` if process is running)
- **`/ready`** - Readiness check (`200 OK` if backends configured, `503` otherwise) - for Kubernetes readiness probes
- **`/live`** - Liveness check (`200 OK` if process is running) - for Kubernetes liveness probes
- **`/metrics`** - Prometheus metrics endpoint

All endpoints return JSON responses (except `/metrics` which returns Prometheus format) and follow Kubernetes health
check conventions.

## Performance

- **Fingerprinting Overhead**: ~2.2% (minimal impact)
- **Concurrent Connections**: Handles thousands of concurrent connections
- **Latency**: Sub-millisecond overhead for fingerprint extraction

See [`benches/README.md`](benches/README.md) for detailed benchmark results from development environment.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for a detailed list of planned features and upcoming phases.

## Related Projects

- **[Huginn Net](https://github.com/biandratti/huginn-net)** - Multi-protocol passive fingerprinting library
- **[huginn-net-tls](https://crates.io/crates/huginn-net-tls)** - JA4 TLS fingerprinting
- **[huginn-net-http](https://crates.io/crates/huginn-net-http)** - HTTP/2 Akamai fingerprinting

## Artifacts Matrix

Each release publishes the following artifacts:

| Suffix | OS | eBPF |
|---|---|---|
| `x86_64-unknown-linux-musl` | Linux amd64 | ❌ |
| `aarch64-unknown-linux-musl` | Linux arm64 | ❌ |
| `x86_64-unknown-linux-musl-ebpf` | Linux amd64 | ✅ |
| `aarch64-unknown-linux-musl-ebpf` | Linux arm64 | ✅ |
| `x86_64-apple-darwin` | macOS amd64 | ❌ |
| `aarch64-apple-darwin` | macOS arm64 | ❌ |

eBPF variants require `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`. All artifacts follow the pattern `huginn-proxy-{tag}-{suffix}`.

Docker images (`ghcr.io/biandratti/huginn-proxy`) are built with eBPF support. See [EBPF-SETUP.md](EBPF-SETUP.md) for runtime requirements.

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
