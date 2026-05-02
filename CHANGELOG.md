# Changelog

All notable changes to huginn-proxy are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.1.0-rc1] — upcoming

First public release candidate.

### Added

**Fingerprinting**
- TLS (JA4) fingerprinting via ClientHello — injects `x-huginn-net-ja4`, `x-huginn-net-ja4_r`, `x-huginn-net-ja4_o`, `x-huginn-net-ja4_or`
- HTTP/2 (Akamai) fingerprinting from SETTINGS and WINDOW_UPDATE frames — injects `x-huginn-net-akamai`
- TCP SYN (p0f-style) fingerprinting via eBPF/XDP — injects `x-huginn-net-tcp` (requires `ebpf-tcp` build feature and Linux kernel ≥ 5.11)
- Per-route `fingerprinting` toggle for TLS and HTTP/2; TCP SYN is global

**Proxying**
- HTTP/1.1 and HTTP/2 support with ALPN negotiation
- IPv4 and IPv6 dual-stack
- Path-prefix routing — longest prefix wins; strip and rewrite support via `replace_path`
- Round-robin load balancing across multiple backends per route
- Connection pooling (HTTP/1.1 and HTTP/2) with `force_new_connection` per-route override
- `preserve_host` for virtual hosting scenarios
- `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Port`, `X-Forwarded-Proto` injection

**Backends**
- Optional active health checks per backend — TCP connect or HTTP `GET` with configurable thresholds
- Fast-fail 502 when backend is marked unhealthy

**Security**
- TLS termination with configurable cipher suites, curves, and TLS version bounds
- TLS session resumption (TLS 1.2 session IDs, TLS 1.3 session tickets)
- Certificate hot reload via file watcher
- mTLS client certificate authentication
- IP filtering — allowlist/denylist with CIDR notation (IPv4 and IPv6)
- Token bucket rate limiting — global and per-route, keyed by IP, header, route, or combined
- Connection limit (`max_connections`)
- HSTS, CSP, and custom security response headers

**Configuration**
- TOML and YAML config formats (detected from file extension)
- Dynamic hot reload via SIGHUP or `--watch` file watcher — zero dropped connections
- Config validation via `--validate` flag
- `[headers]` global and per-route request/response header manipulation

**Observability**
- 44 Prometheus metrics covering connections, requests, TLS, fingerprinting, backends, health checks, rate limiting, IP filtering, headers, mTLS, config reload, and build info
- Health endpoints: `/health`, `/ready`, `/live`, `/metrics`
- Pre-built Grafana dashboard with Prometheus provisioning (`examples/docker-compose.observability.yml`)

**Deployment**
- Docker images: `huginn-proxy` (eBPF), `huginn-proxy-plain` (no eBPF), `huginn-proxy-ebpf-agent`
- Static release binaries for Linux (amd64/arm64, musl and glibc) and macOS (amd64/arm64)
- Docker Compose examples for full eBPF stack and plain stack
- Kubernetes deployment examples (DaemonSet for eBPF agent, Deployment for proxy)

---

[Unreleased]: https://github.com/biandratti/huginn-proxy/compare/v0.1.0-rc1...HEAD
[0.1.0-rc1]: https://github.com/biandratti/huginn-proxy/releases/tag/v0.1.0-rc1
