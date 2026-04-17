# Configuration Reference

All configuration is read from a single TOML file. Pass it via CLI or environment variable:

```bash
huginn-proxy config.toml
huginn-proxy --config config.toml
HUGINN_CONFIG_PATH=config.toml huginn-proxy
```

Validate a config file without starting the proxy (like `nginx -t`):

```bash
huginn-proxy --validate config.toml
```

**Hot reload:** dynamic sections update on SIGHUP or file-watcher trigger without dropping connections. Static sections
require a process restart — changes are logged as a warning and ignored. See [DEPLOYMENT.md](DEPLOYMENT.md) for the full
static/dynamic split.

---

## Top-level keys

These bare keys must appear **before** any `[table]` header in the file (TOML requirement).

| Key             | Type | Default | Description                                                                                                                                     |
|-----------------|------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `preserve_host` | bool | `false` | Forward the original `Host` header from the client to the backend. When `false`, the proxy substitutes its own `Host` with the backend address. |

```toml
preserve_host = false
```

---

## `[listen]`

Network interfaces and socket options. **Static** — requires restart to change.

| Key           | Type             | Default | Description                                                                            |
|---------------|------------------|---------|----------------------------------------------------------------------------------------|
| `addrs`       | array of strings | —       | One or more `host:port` addresses to bind. IPv6 addresses must be wrapped in brackets. |
| `tcp_backlog` | integer          | `4096`  | Kernel `listen(2)` backlog per socket. Increase under heavy connection bursts.         |

```toml
[listen]
addrs = ["0.0.0.0:7000", "[::]:7000"]
# tcp_backlog = 4096
```

---

## `[[backends]]`

Backend servers for forwarding. Repeat the header for each backend. **Dynamic** (hot-reloadable).

| Key            | Type   | Default           | Description                                                                                                                        |
|----------------|--------|-------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `address`      | string | —                 | `host:port` of the backend. Used as the pool key — must match exactly what routes reference.                                       |
| `http_version` | string | `null` (preserve) | Protocol to use when connecting to this backend. `"http11"`, `"http2"`, or `"preserve"` (negotiate based on what the client used). |

```toml
[[backends]]
address = "backend-a:9000"
http_version = "preserve"

[[backends]]
address = "backend-b:9000"
http_version = "http11"
```

---

## `[[routes]]`

Path-prefix routing rules. **First match wins** — order matters. **Dynamic** (hot-reloadable).

| Key                    | Type   | Default | Description                                                                                                                                                                                    |
|------------------------|--------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `prefix`               | string | —       | URL path prefix to match. Use `"/"` as a catch-all default route.                                                                                                                              |
| `backend`              | string | —       | Backend address to forward to. Must match a `[[backends]].address` exactly.                                                                                                                    |
| `fingerprinting`       | bool   | `true`  | Inject TLS/HTTP fingerprint headers (`x-huginn-net-*`) for this route.                                                                                                                         |
| `force_new_connection` | bool   | `false` | Bypass the connection pool — opens a fresh TCP+TLS connection per request. Required when you need a fresh TLS handshake for each request (e.g. JA4 extraction on every request). Adds latency. |
| `replace_path`         | string | `null`  | Path prefix replacement. Empty string (`""`) strips the prefix. Any other value replaces the matched prefix. Absent = forward as-is.                                                           |
| `rate_limit`           | table  | —       | Per-route rate limit overrides. See [`[routes.rate_limit]`](#routesrate_limit) below.                                                                                                          |
| `headers`              | table  | —       | Per-route header manipulation. Same shape as [`[headers]`](#headers).                                                                                                                          |

```toml
# Forward /api to backend-a, with fingerprinting
[[routes]]
prefix = "/api"
backend = "backend-a:9000"
fingerprinting = true

# Strip /strip prefix: /strip/users → /users
[[routes]]
prefix = "/strip"
backend = "backend-a:9000"
replace_path = ""

# Rewrite /old prefix: /old/data → /new/data
[[routes]]
prefix = "/old"
backend = "backend-b:9000"
replace_path = "/new"

# Catch-all
[[routes]]
prefix = "/"
backend = "backend-b:9000"
```

### `[routes.rate_limit]`

Overrides the global `[security.rate_limit]` for this specific route. Only the keys you set override the global; unset
keys fall back to the global config.

| Key                   | Type    | Default | Description                                                               |
|-----------------------|---------|---------|---------------------------------------------------------------------------|
| `enabled`             | bool    | `null`  | Override whether rate limiting is active for this route.                  |
| `requests_per_second` | integer | `null`  | Override RPS limit.                                                       |
| `burst`               | integer | `null`  | Override burst size.                                                      |
| `limit_by`            | string  | `null`  | Override limit key strategy: `"ip"`, `"header"`, `"route"`, `"combined"`. |
| `limit_by_header`     | string  | `null`  | Override header name when `limit_by = "header"`.                          |

```toml
[[routes]]
prefix = "/api"
backend = "backend-a:9000"

[routes.rate_limit]
enabled = true
requests_per_second = 50
burst = 100
limit_by = "combined"

[[routes]]
prefix = "/public"
backend = "backend-b:9000"

[routes.rate_limit]
enabled = false   # disable rate limiting for this route
```

### `[routes.headers]`

Per-route header manipulation. Same shape as [`[headers]`](#headers). Applied after global headers.

```toml
[[routes]]
prefix = "/api"
backend = "backend-a:9000"

[routes.headers.request]
add = [{ name = "X-Internal-Route", value = "api" }]

[routes.headers.response]
remove = ["X-Backend-Id"]
```

---

## `[headers]`

Global header manipulation applied to every request/response. **Dynamic** (hot-reloadable).

### `[headers.request]`

| Key      | Type                     | Default | Description                                                            |
|----------|--------------------------|---------|------------------------------------------------------------------------|
| `add`    | array of `{name, value}` | `[]`    | Headers to add to the upstream request. Overwrites if already present. |
| `remove` | array of strings         | `[]`    | Header names to remove from the upstream request.                      |

### `[headers.response]`

| Key      | Type                     | Default | Description                                      |
|----------|--------------------------|---------|--------------------------------------------------|
| `add`    | array of `{name, value}` | `[]`    | Headers to add to the client response.           |
| `remove` | array of strings         | `[]`    | Header names to remove from the client response. |

```toml
[headers.request]
remove = ["X-Forwarded-Server"]
add = [
    { name = "X-Proxy-Name", value = "huginn-proxy" },
]

[headers.response]
remove = ["Server", "X-Powered-By"]
add = [
    { name = "X-Proxy", value = "huginn-proxy" },
]
```

---

## `[tls]`

TLS termination. Omit the entire section to run as plain HTTP. **Static** — requires restart to change (cert/key file
contents are hot-reloaded separately via file watcher).

| Key         | Type             | Default | Description                                                                                                 |
|-------------|------------------|---------|-------------------------------------------------------------------------------------------------------------|
| `cert_path` | string           | —       | Path to the server certificate PEM file.                                                                    |
| `key_path`  | string           | —       | Path to the private key PEM file.                                                                           |
| `alpn`      | array of strings | `[]`    | ALPN protocols to advertise. Use `["h2", "http/1.1"]` to support both HTTP/2 and HTTP/1.1 with negotiation. |

```toml
[tls]
cert_path = "/config/certs/server.crt"
key_path = "/config/certs/server.key"
alpn = ["h2", "http/1.1"]
```

### `[tls.options]`

| Key                 | Type             | Default          | Description                                                |
|---------------------|------------------|------------------|------------------------------------------------------------|
| `versions`          | array of strings | `["1.2", "1.3"]` | Allowed TLS versions. Values: `"1.2"`, `"1.3"`.            |
| `cipher_suites`     | array of strings | all supported    | Named cipher suites. Restrict to tighten security posture. |
| `curve_preferences` | array of strings | all supported    | Named elliptic curves for key exchange.                    |

```toml
[tls.options]
versions = ["1.2", "1.3"]
cipher_suites = [
    "TLS13_AES_128_GCM_SHA256",
    "TLS13_AES_256_GCM_SHA384",
    "TLS13_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
]
curve_preferences = ["X25519", "secp256r1", "secp384r1"]
```

### `[tls.client_auth]`

Mutual TLS (mTLS). Omit to disable. **Static**.

```toml
# Require client certificates signed by this CA
[tls.client_auth]
required = { ca_cert_path = "/config/certs/ca.crt" }
```

### `[tls.session_resumption]`

| Key            | Type    | Default | Description                                                                    |
|----------------|---------|---------|--------------------------------------------------------------------------------|
| `enabled`      | bool    | `true`  | Enable TLS session resumption (TLS 1.2 session IDs + TLS 1.3 session tickets). |
| `max_sessions` | integer | `256`   | TLS 1.2 server-side session cache size.                                        |

```toml
[tls.session_resumption]
enabled = true
max_sessions = 256
```

---

## `[fingerprint]`

Feature flags for passive fingerprinting. **Static** — eBPF programs are loaded at startup.

| Key            | Type    | Default | Description                                                                                                                                                |
|----------------|---------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `tls_enabled`  | bool    | `true`  | Extract TLS (JA4) fingerprints and inject `x-huginn-net-ja4*` headers.                                                                                     |
| `http_enabled` | bool    | `true`  | Extract HTTP/2 (Akamai) fingerprints and inject `x-huginn-net-akamai` header.                                                                              |
| `tcp_enabled`  | bool    | `false` | Extract TCP SYN (p0f-style) fingerprints via eBPF/XDP and inject `x-huginn-net-tcp` header. Requires the `ebpf-tcp` build feature and Linux kernel ≥ 5.11. |
| `max_capture`  | integer | `65536` | Maximum bytes captured per HTTP/2 connection for fingerprinting.                                                                                           |

```toml
[fingerprint]
tls_enabled = true
http_enabled = true
tcp_enabled = false
max_capture = 65536
```

---

## `[logging]`

**Static** — logger is initialized once at startup.

| Key           | Type   | Default  | Description                                                                                                           |
|---------------|--------|----------|-----------------------------------------------------------------------------------------------------------------------|
| `level`       | string | `"info"` | Log level: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`. Overridable with the `RUST_LOG` environment variable. |
| `show_target` | bool   | `false`  | Include the Rust module path in log lines (useful for debugging).                                                     |

```toml
[logging]
level = "info"
show_target = false
```

---

## `[telemetry]`

Metrics server and OpenTelemetry settings. **Static** — the metrics listener binds at startup.

| Key              | Type    | Default  | Description                                                                                                                       |
|------------------|---------|----------|-----------------------------------------------------------------------------------------------------------------------------------|
| `metrics_port`   | integer | `null`   | Port for the Prometheus metrics + health-check HTTP server. Omit to disable. Endpoints: `/metrics`, `/health`, `/ready`, `/live`. |
| `otel_log_level` | string  | `"warn"` | OpenTelemetry SDK internal log level. Does not affect application logs.                                                           |

```toml
[telemetry]
metrics_port = 9090
otel_log_level = "warn"
```

---

## `[timeout]`

Connection timeout controls. **Static** — applied once at startup; the connection pool and acceptor are built with these
values.

| Key                        | Type    | Default             | Description                                                                                                                           |
|----------------------------|---------|---------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| `upstream_connect_ms`      | integer | absent (no timeout) | TCP connect timeout to backend in milliseconds. Absent or omitted = no timeout.                                                       |
| `proxy_idle_ms`            | integer | `60000`             | Inbound idle timeout in milliseconds. Applied as HTTP/1.1 `header_read_timeout` and HTTP/2 keep-alive interval.                       |
| `tls_handshake_secs`       | integer | `15`                | Maximum seconds to complete the client TLS handshake. Slow/malicious clients that stall the handshake are disconnected.               |
| `connection_handling_secs` | integer | `300`               | Maximum total seconds for a full connection lifecycle (read request + proxy + write response). Guards against extremely slow clients. |
| `shutdown_secs`            | integer | `30`                | Graceful shutdown window. In-flight requests have this many seconds to complete before the process exits.                             |

```toml
[timeout]
upstream_connect_ms = 5000
proxy_idle_ms = 60000
tls_handshake_secs = 15
connection_handling_secs = 300
shutdown_secs = 30
```

### `[timeout.keep_alive]`

HTTP/1.1 keep-alive and upstream TCP keepalive. Applies only to HTTP/1.1; HTTP/2 connections are always persistent.

| Key                     | Type    | Default | Description                                                                                                                                                                                   |
|-------------------------|---------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `enabled`               | bool    | `true`  | Enable HTTP/1.1 persistent connections (`Connection: keep-alive`).                                                                                                                            |
| `upstream_idle_timeout` | integer | `60`    | TCP keepalive interval in seconds for proxy → backend connections. Sets how often keepalive packets are sent to detect dead backend connections. Aligned with rpxy's `upstream_idle_timeout`. |

```toml
[timeout.keep_alive]
enabled = true
upstream_idle_timeout = 60
```

---

## `[backend_pool]`

HTTP connection pool for proxy → backend connections. **Dynamic** (hot-reloadable). Changing this triggers pool
recreation and draining of old connections.

| Key                      | Type    | Default | Description                                                                                                            |
|--------------------------|---------|---------|------------------------------------------------------------------------------------------------------------------------|
| `enabled`                | bool    | `true`  | Enable connection pooling. Set to `false` to open a new connection for every request (not recommended for production). |
| `idle_timeout`           | integer | `90`    | Seconds before an idle pooled connection is closed and removed.                                                        |
| `pool_max_idle_per_host` | integer | `0`     | Maximum idle connections kept per backend host. `0` = unlimited.                                                       |

```toml
[backend_pool]
enabled = true
idle_timeout = 90
pool_max_idle_per_host = 0
```

---

## `[security]`

### Top-level security keys

| Key               | Type    | Default | Description                                                                         |
|-------------------|---------|---------|-------------------------------------------------------------------------------------|
| `max_connections` | integer | `512`   | Maximum concurrent client connections. **Static** — enforced at the acceptor level. |

```toml
[security]
max_connections = 512
```

### `[security.ip_filter]`

IP-based access control. **Dynamic** (hot-reloadable).

| Key         | Type             | Default      | Description                                                                                                |
|-------------|------------------|--------------|------------------------------------------------------------------------------------------------------------|
| `mode`      | string           | `"disabled"` | Filter mode: `"disabled"`, `"allowlist"` (only listed IPs pass), or `"denylist"` (listed IPs are blocked). |
| `allowlist` | array of strings | `[]`         | CIDR ranges allowed when `mode = "allowlist"`. Supports IPv4 and IPv6. Empty allowlist blocks all traffic. |
| `denylist`  | array of strings | `[]`         | CIDR ranges blocked when `mode = "denylist"`. Supports IPv4 and IPv6. Empty denylist allows all traffic.   |

```toml
# Disabled (default)
[security.ip_filter]
mode = "disabled"

# Allowlist: only these IPs can connect
[security.ip_filter]
mode = "allowlist"
allowlist = ["10.0.0.0/8", "192.168.1.0/24", "::1/128"]

# Denylist: block these IPs
[security.ip_filter]
mode = "denylist"
denylist = ["192.168.1.100/32", "10.99.0.0/16"]
```

### `[security.rate_limit]`

Global rate limiting. **Dynamic** (hot-reloadable). Per-route overrides via `[routes.rate_limit]`.

| Key                   | Type    | Default | Description                                                                         |
|-----------------------|---------|---------|-------------------------------------------------------------------------------------|
| `enabled`             | bool    | `false` | Enable global rate limiting.                                                        |
| `requests_per_second` | integer | `1000`  | Sustained request rate allowed.                                                     |
| `burst`               | integer | `2000`  | Maximum burst size above the sustained rate.                                        |
| `window_seconds`      | integer | `1`     | Sliding window in seconds for the token bucket refill.                              |
| `limit_by`            | string  | `"ip"`  | Key used to track limits: `"ip"`, `"header"`, `"route"`, `"combined"` (IP + route). |
| `limit_by_header`     | string  | `null`  | Header name to use as the rate limit key when `limit_by = "header"`.                |

```toml
[security.rate_limit]
enabled = true
requests_per_second = 1000
burst = 2000
window_seconds = 1
limit_by = "ip"
```

```toml
# Rate limit by API key header
[security.rate_limit]
enabled = true
requests_per_second = 200
burst = 400
limit_by = "header"
limit_by_header = "X-API-Key"
```

### `[security.headers]`

Security headers added to every response. **Dynamic** (hot-reloadable).

| Key      | Type                     | Default | Description                               |
|----------|--------------------------|---------|-------------------------------------------|
| `custom` | array of `{name, value}` | `[]`    | Arbitrary headers added to all responses. |

```toml
[security.headers]
custom = [
    { name = "X-Frame-Options", value = "DENY" },
    { name = "X-Content-Type-Options", value = "nosniff" },
    { name = "Referrer-Policy", value = "strict-origin-when-cross-origin" },
]
```

#### `[security.headers.hsts]`

HTTP Strict Transport Security. Only meaningful when TLS is enabled.

| Key                  | Type    | Default    | Description                                                 |
|----------------------|---------|------------|-------------------------------------------------------------|
| `enabled`            | bool    | `false`    | Add `Strict-Transport-Security` header to responses.        |
| `max_age`            | integer | `31536000` | `max-age` in seconds (default = 1 year).                    |
| `include_subdomains` | bool    | `false`    | Add `includeSubDomains` directive.                          |
| `preload`            | bool    | `false`    | Add `preload` directive (for HSTS preload list submission). |

```toml
[security.headers.hsts]
enabled = true
max_age = 31536000
include_subdomains = true
preload = false
```

#### `[security.headers.csp]`

Content Security Policy.

| Key       | Type   | Default                | Description                                        |
|-----------|--------|------------------------|----------------------------------------------------|
| `enabled` | bool   | `false`                | Add `Content-Security-Policy` header to responses. |
| `policy`  | string | `"default-src 'self'"` | Full CSP policy string.                            |

```toml
[security.headers.csp]
enabled = true
policy = "default-src 'self'; script-src 'self' 'unsafe-inline'"
```

---

## Complete minimal example

```toml
preserve_host = false

[listen]
addrs = ["0.0.0.0:8080"]

[[backends]]
address = "localhost:3000"

[[routes]]
prefix = "/"
backend = "localhost:3000"
```

## Complete production example

See [`examples/config/compose.toml`](examples/config/compose.toml).
