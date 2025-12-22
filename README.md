# Huginn Proxy

Reverse proxy focused on fingerprinting (TCP SYN, HTTP, TLS) with high-performance L4 forwarding and optional TLS termination.

## Goals
- L4-first design: fast TCP forwarding with minimal overhead.
- TLS termination to inspect and route HTTP.
- Fingerprinting-first: inject fingerprints to backends via headers (`X-Huginn-TCP-FP`, `X-Huginn-HTTP-FP`, `X-Huginn-TLS-F`).
- No WebSocket/upgrade features or heavy L7 extras; simple HTTP/1.1 routing via peeking or after TLS termination.

## Fingerprints sent to backend
- `X-Huginn-TCP-FP`: hash + key TCP SYN options (MSS, WS, SACK, TS, order).
- `X-Huginn-HTTP-FP`: HTTP/1.1 request line + header order (cleartext or after TLS termination).
- `X-Huginn-TLS-F`: ClientHello fingerprint (ciphers, ALPN, extensions/order) when TLS is terminated.

## Quick run
- Prerequisites: Rust (MSRV 1.82), `cargo`.
- Run the binary with a TOML config:
  - `cargo run -p huginn-proxy -- examples/config/basic.toml`
  - Minimal expected config:
    - `listen = "127.0.0.1:7000"`
    - `backends = [{ address = "127.0.0.1:9000" }]`
    - `peek_http = true|false`
    - `[http] routes = []` (optional prefix routing)
    - `[telemetry] basic_metrics = true/false; metrics_addr = "127.0.0.1:9900"` (required when metrics are enabled)
    - `[timeouts] connect_ms`, `idle_ms`
  - Prometheus metrics (if `telemetry.basic_metrics` is enabled):
    - `curl http://<metrics_addr>/metrics`

With Docker Compose (includes two backends and Prometheus metrics):
- `docker compose -f examples/docker-compose.yml up --build`
- Proxy listens on `localhost:7000`, metrics on `localhost:9900`.