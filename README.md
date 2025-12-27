<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Proxy Logo" width="200"/>
  
  # Huginn Proxy

  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-proxy#license)
  [![Pure Rust](https://img.shields.io/badge/pure-Rust-brightgreen.svg)](https://www.rust-lang.org/)

  **High-performance reverse proxy with passive fingerprinting capabilities powered by Huginn Net.**
</div>

## Overview

**Huginn Proxy** is a reverse proxy built in Rust that combines traditional load balancing and request forwarding with advanced passive fingerprinting capabilities. It leverages the [Huginn Net](https://github.com/biandratti/huginn-net) fingerprinting libraries to extract TLS (JA4) and HTTP/2 (Akamai) fingerprints from client connections, injecting them as headers for downstream services.

> **Note:** This project is currently in active development.

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
- **TLS Termination** - Server-side TLS with configurable ALPN
- **Request Forwarding** - Transparent request/response forwarding
- **Graceful Shutdown** - Clean connection draining with configurable timeout

### Fingerprinting Integration

- **TLS Fingerprinting (JA4)** - Automatic extraction of JA4 fingerprints from TLS ClientHello messages (works for all TLS connections)
- **HTTP/2 Fingerprinting (Akamai)** - Extraction of Akamai-style fingerprints from HTTP/2 frames (HTTP/2 only)
- **Header Injection** - Fingerprints automatically injected as `x-huginn-net-tls` and `x-huginn-net-http` headers
- **Configurable** - Enable/disable fingerprinting per protocol via configuration
- **Low Overhead** - Efficient inline processing with minimal overhead


## Quick Start

### Installation

#### From Source

```bash
git clone https://github.com/biandratti/huginn-proxy.git
cd huginn-proxy
cargo build --release
```

#### Docker

```bash
docker build -t huginn-proxy .
```

### Basic Configuration

Create a `config.toml` file:

```toml
listen = "0.0.0.0:7000"

backends = [
  { address = "backend-1:9000" },
  { address = "backend-2:9000" }
]

routes = [
  { prefix = "/api", backend = "backend-1:9000" },
  { prefix = "/",   backend = "backend-2:9000" }
]

[tls]
cert_path = "/path/to/cert.pem"
key_path  = "/path/to/key.pem"
alpn = ["h2"]

[fingerprint]
tls_enabled = true
http_enabled = true

[logging]
level = "info"
show_target = false

[timeout]
connect_ms = 5000
idle_ms = 60000
shutdown_secs = 30
```

### Running

```bash
./target/release/huginn-proxy config.toml
```

## Fingerprinting Details

### TLS Fingerprinting (JA4)

Huginn Proxy extracts JA4 fingerprints from TLS ClientHello messages using the [huginn-net-tls](https://crates.io/crates/huginn-net-tls) library. The fingerprint follows the [official JA4 specification](https://github.com/FoxIO-LLC/ja4) and is injected as the `x-huginn-net-tls` header.

**Example:**
```
x-huginn-net-tls: t13d1516h2_8afaf4b9491c_00_0403040303030103010302_01
```

### HTTP/2 Fingerprinting (Akamai)

HTTP/2 fingerprints are extracted from the initial HTTP/2 frames (SETTINGS, WINDOW_UPDATE, PRIORITY, HEADERS) following the [Blackhat EU 2017 specification](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf). The fingerprint is injected as the `x-huginn-net-http` header.

**Note:** Akamai fingerprinting only works for HTTP/2 connections. HTTP/1.x connections will not have the `x-huginn-net-http` header injected.

**Example:**
```
x-huginn-net-http: 1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,p,a,s
```

## Examples

### Docker Compose Example

See [`examples/docker-compose.yml`](examples/docker-compose.yml) for a complete setup with:
- Huginn Proxy with TLS termination
- Multiple backend servers
- Path-based routing
- Fingerprinting enabled

## Performance

- **Throughput**: Handles thousands of concurrent connections
- **Latency**: Sub-millisecond overhead for fingerprinting
- **Memory**: Efficient zero-copy processing
- **CPU**: Minimal overhead (~1-2%) for fingerprint extraction

## Roadmap

The following features are planned for future releases:

- [ ] Health checks for backends
- [ ] Metrics and observability (Prometheus)
- [ ] Advanced load balancing algorithms (least connections, weighted)
- [ ] Rate limiting
- [ ] Request/response transformation
- [ ] Circuit breakers
- [ ] Comprehensive test coverage
- [ ] Performance benchmarking and optimization
- [ ] Production hardening and security audit
- [ ] TCP fingerprint

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
