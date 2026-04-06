---
title: Quick example
description: Sample TOML snippet. Beta.
sidebar:
  order: 2
---

## Example `config.toml`

```toml
backends = [
    { address = "backend-a:9000", http_version = "preserve" },
    { address = "backend-b:9000", http_version = "preserve" },
]

routes = [
    { prefix = "/api", backend = "backend-a:9000", fingerprinting = true, force_new_connection = false },
    { prefix = "/", backend = "backend-b:9000" },
]

preserve_host = false

[listen]
addrs = ["0.0.0.0:7000", "[::]:7000"]

[tls]
cert_path = "/config/certs/server.crt"
key_path = "/config/certs/server.key"
alpn = ["h2", "http/1.1"]
watch_delay_secs = 60

[fingerprint]
tls_enabled = true
http_enabled = true
tcp_enabled = true

[telemetry]
metrics_port = 9090
```

Adjust hostnames (`backend-a`, `backend-b`) and paths to match your Compose service names or local backends. For TLS, point `cert_path` / `key_path` at real files (or use plain HTTP by omitting `[tls]` during local tests).

## Observability

With `telemetry.metrics_port` set, health and metrics are on **that** port, not the main listener:

- `GET /health`, `GET /ready`, `GET /live`, `GET /metrics`

Details: [Telemetry](telemetry/).
