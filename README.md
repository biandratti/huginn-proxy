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

**Huginn Proxy** is a reverse proxy built in Rust that combines traditional load balancing and request forwarding with advanced passive fingerprinting capabilities. It leverages the [Huginn Net](https://github.com/biandratti/huginn-net) fingerprinting libraries to extract TLS (JA4) and HTTP/2 (Akamai) fingerprints from client connections, injecting them as headers for downstream services.

Inspired by production-grade proxies like [Pingora](https://github.com/cloudflare/pingora), [Sozu](https://github.com/sozu-proxy/sozu), and [rust-rpxy](https://github.com/junkurihara/rust-rpxy).

> **Note:** This project is currently in active development.

## Quick Start

### Build

```bash
cargo build --release
```

### Minimal Configuration

Create `config.toml`:

```toml
listen = "0.0.0.0:7000"

backends = [
  { address = "backend:8080", http_version = "preserve" }
]

routes = [
  { prefix = "/", backend = "backend:8080" }
]

[tls]
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"
alpn = ["h2", "http/1.1"]

[fingerprint]
tls_enabled = true
http_enabled = true
```

## Installation

### From Source

```bash
git clone https://github.com/biandratti/huginn-proxy.git
cd huginn-proxy
cargo build --release
```

### Docker

```bash
docker build -t huginn-proxy .
docker run -v /path/to/config.toml:/config.toml huginn-proxy /config.toml
```

## Features

- **HTTP/1.x & HTTP/2** - Full support for both protocol versions
- **Load Balancing** - Round-robin load balancing across multiple backends
- **Path-based Routing** - Route matching with prefix support, path stripping, and path rewriting
- **Rate Limiting** - Token bucket algorithm with multiple strategies (IP, Header, Route, Combined), global and per-route limits
- **Security Headers** - HSTS, CSP, X-Frame-Options, and custom headers
- **IP Filtering (ACL)** - Allowlist/denylist with CIDR notation support
- **TLS Termination** - Server-side TLS with ALPN, certificate hot reload (single certificate per configuration)
- **mTLS (Mutual TLS)** - Client certificate authentication for secure service-to-service communication
- **Host Header Preservation** - Configurable forwarding of original Host header for virtual hosting
- **Passive Fingerprinting** - Automatic TLS (JA4) and HTTP/2 (Akamai) fingerprint extraction
- **X-Forwarded-* Headers** - Automatic injection of proxy forwarding headers
- **High Performance** - Built on Tokio and Hyper
- **Easy Deployment** - Single binary, Docker-ready

See [FEATURES.md](FEATURES.md) for detailed descriptions and limitations of each feature.

## Fingerprinting

Fingerprints are automatically extracted and injected as headers:

- **TLS (JA4)**: `x-huginn-net-ja4` - Extracted from all TLS connections using [huginn-net-tls](https://crates.io/crates/huginn-net-tls)
- **HTTP/2 (Akamai)**: `x-huginn-net-akamai` - Extracted from HTTP/2 connections only using [huginn-net-http](https://crates.io/crates/huginn-net-http)

**Examples:**
```
x-huginn-net-ja4: t13d1516h2_8afaf4b9491c_00_0403040303030103010302_01
x-huginn-net-akamai: 1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,p,a,s
```

See [JA4 specification](https://github.com/FoxIO-LLC/ja4) and [Blackhat EU 2017](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf) for details.

## Proxy Headers

The proxy automatically injects standard `X-Forwarded-*` headers to inform backends about the original client request:

- **X-Forwarded-For**: Client IP address (appended if already present)
- **X-Forwarded-Host**: Original Host header value
- **X-Forwarded-Port**: Client port number
- **X-Forwarded-Proto**: Protocol used (`http` or `https`)

These headers always override any client-provided values to prevent spoofing.

## Health Check Endpoints

When `telemetry.metrics_port` is configured, Huginn Proxy exposes health check endpoints on the observability server (separate from the main proxy port):

- **`/health`** - General health check (`200 OK` if process is running)
- **`/ready`** - Readiness check (`200 OK` if backends configured, `503` otherwise) - for Kubernetes readiness probes
- **`/live`** - Liveness check (`200 OK` if process is running) - for Kubernetes liveness probes
- **`/metrics`** - Prometheus metrics endpoint

All endpoints return JSON responses (except `/metrics` which returns Prometheus format) and follow Kubernetes health check conventions.

## Examples

See the [`examples/`](examples/) directory for:
- Docker Compose setup with TLS termination
- Rate limiting configurations
- Advanced routing examples

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

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).

### Attribution

Huginn Proxy uses the [Huginn Net](https://github.com/biandratti/huginn-net) fingerprinting libraries:

- **JA4**: TLS fingerprinting follows the [JA4 specification by FoxIO, LLC](https://github.com/FoxIO-LLC/ja4)
- **Akamai HTTP/2**: HTTP/2 fingerprinting follows the [Blackhat EU 2017 specification](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)

## Contributing

Contributions are welcome! Please see our contributing guidelines for details.
