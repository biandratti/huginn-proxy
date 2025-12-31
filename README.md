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

### Why choose Huginn Proxy?

- **Reverse Proxy** - HTTP/1.x and HTTP/2 reverse proxy with load balancing
- **Passive Fingerprinting** - Automatic TLS (JA4) fingerprint extraction for all TLS connections, and HTTP/2 (Akamai) fingerprint extraction for HTTP/2 connections
- **High Performance** - Built on Tokio and Hyper for maximum throughput
- **Easy Deployment** - Single binary, Docker-ready, minimal dependencies

## Features

### Core Proxy Capabilities

- **HTTP/1.x & HTTP/2** - Full support for both protocol versions
- **Load Balancing** - Round-robin load balancing across multiple backends
- **Route Matching** - Path-based routing with prefix matching
- **TLS Termination** - Server-side TLS with configurable ALPN, supports PEM certificates (PKCS#8/RSA keys), hot reload for zero-downtime certificate updates, single certificate per instance (no SNI/mTLS)

### Fingerprinting Integration

- **TLS Fingerprinting (JA4)** - Automatic extraction of JA4 fingerprints from TLS ClientHello messages (works for all TLS connections)
- **HTTP/2 Fingerprinting (Akamai)** - Extraction of Akamai-style fingerprints from HTTP/2 frames (HTTP/2 only)
- **Header Injection** - Fingerprints automatically injected as `x-huginn-net-tls` and `x-huginn-net-http` headers
- **Configurable** - Enable/disable fingerprinting per protocol via configuration

## Fingerprinting

Fingerprints are automatically extracted and injected as headers:

- **TLS (JA4)**: `x-huginn-net-tls` - Extracted from all TLS connections using [huginn-net-tls](https://crates.io/crates/huginn-net-tls)
- **HTTP/2 (Akamai)**: `x-huginn-net-http` - Extracted from HTTP/2 connections only using [huginn-net-http](https://crates.io/crates/huginn-net-http)

**Examples:**
```
x-huginn-net-tls: t13d1516h2_8afaf4b9491c_00_0403040303030103010302_01
x-huginn-net-http: 1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,p,a,s
```

See [JA4 specification](https://github.com/FoxIO-LLC/ja4) and [Blackhat EU 2017](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf) for details.

## Examples

### Basic Configuration

```toml
listen = "0.0.0.0:7000"

backends = [
  { address = "backend-a:8080", http_version = "preserve" },
  { address = "backend-b:8080", http_version = "preserve" }
]

routes = [
  { prefix = "/api", backend = "backend-a:8080", fingerprinting = true },
  { prefix = "/static", backend = "backend-b:8080", fingerprinting = false }
]

[tls]
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"
alpn = ["h2", "http/1.1"]
```

### Docker Compose

See [`examples/docker-compose.yml`](examples/docker-compose.yml) for a complete setup with TLS termination, multiple backends, and path-based routing.

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
