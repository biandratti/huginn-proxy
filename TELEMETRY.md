# Telemetry Documentation

> **Status**: This document covers currently implemented telemetry features for both **Huginn Proxy** and the **eBPF
agent**.

## Overview

### Proxy

Huginn Proxy provides comprehensive telemetry through:

- **Prometheus Metrics** - 51 metrics covering connections, PROXY protocol, requests, TLS, fingerprinting, backends, active health
  checks, throughput, rate limiting, IP filtering, header manipulation, mTLS, config hot reload, TLS certificate
  hot reload, and fingerprint spoofing detection
- **Health Check Endpoints** - Kubernetes-ready: `/health`, `/ready`, `/live`, `/metrics`
- **Structured Logs** - one secret-safe effective-config summary at startup (`info`), with the
  complete redacted effective config available at `debug`

All proxy telemetry is exposed on a separate observability server (configurable via `telemetry.metrics_port`).
One-shot `--validate` / `--print-effective-config` commands initialize warning-level diagnostics
on stderr; stdout remains either `Config OK` or valid effective-config JSON.

### eBPF Agent

The eBPF agent (DaemonSet) exposes the **same four HTTP endpoints** as the proxy for K8s compatibility, plus its own
Prometheus metrics:

- **Endpoints** - `/health`, `/ready`, `/live`, `/metrics` (same JSON format as proxy; `/ready` returns 503 when BPF map
  pins are missing)
- **Metrics** - `tcp_syn_captured_total`, `tcp_syn_insert_failures_total`, `tcp_syn_malformed_total`, `agent_up`,
  `huginn_ebpf_agent_build_info`

---

## Configuration

### Proxy

```toml
[telemetry]
metrics_port = 9090  # Port for metrics and health endpoints (default: disabled)
```

When `metrics_port` is configured, the following endpoints become available:

### eBPF Agent

The agent’s observability server is configured via environment variables:

| Variable                   | Required | Description                     |
|----------------------------|----------|---------------------------------|
| `HUGINN_EBPF_METRICS_ADDR` | Yes      | Bind address (e.g. `127.0.0.1`) |
| `HUGINN_EBPF_METRICS_PORT` | Yes      | Port (e.g. `9091`)              |

---

## Metrics Endpoint

**Format**: Prometheus text format (both proxy and agent)  
**Scraping**: Compatible with Prometheus, Grafana Agent, etc.

- **Proxy**: `http://<host>:<telemetry.metrics_port>/metrics` (e.g. `http://localhost:9090/metrics`)
- **eBPF agent**: `http://<HUGINN_EBPF_METRICS_ADDR>:<HUGINN_EBPF_METRICS_PORT>/metrics` (e.g.
  `http://127.0.0.1:9091/metrics`)

### Example Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'huginn-proxy'
    static_configs:
      - targets: [ 'localhost:9090' ]
    scrape_interval: 15s

  - job_name: 'huginn-ebpf-agent'
    static_configs:
      - targets: [ '127.0.0.1:9091' ]
    scrape_interval: 15s
```

---

## Implemented Metrics

### 1. Throughput Metrics

| Metric                                | Type    | Description                        | Labels                               |
|---------------------------------------|---------|------------------------------------|--------------------------------------|
| `huginn_bytes_received_total`         | Counter | Total bytes received from clients  | `protocol`                           |
| `huginn_bytes_sent_total`             | Counter | Total bytes sent to clients        | `protocol`                           |
| `huginn_backend_bytes_received_total` | Counter | Total bytes received from backends | `backend_address`, `route`, `domain` |
| `huginn_backend_bytes_sent_total`     | Counter | Total bytes sent to backends       | `backend_address`, `route`, `domain` |

**Labels**:

- `protocol`: Connection protocol (`http/1.1`, `h2`, `https`)
- `backend_address`: Backend server address (e.g., `backend-1:9000`)
- `route`: Matched route prefix (e.g., `/api`, `/`)
- `domain`: Matched domain — configured `host`, or `_default_` for the catch-all (see §3)

**Example queries**:

```promql
# Client throughput rate (bytes/sec received)
rate(huginn_bytes_received_total[5m])

# Client throughput rate (bytes/sec sent)
rate(huginn_bytes_sent_total[5m])

# Backend throughput rate (bytes/sec)
rate(huginn_backend_bytes_received_total[5m])
rate(huginn_backend_bytes_sent_total[5m])

# Total bandwidth usage (MB/s)
(rate(huginn_bytes_received_total[5m]) + rate(huginn_bytes_sent_total[5m])) / 1024 / 1024

# Per-backend bandwidth
sum by (backend_address) (rate(huginn_backend_bytes_received_total[5m]))
```

**Note**: Throughput metrics are based on `Content-Length` headers when available. Chunked transfer encoding (without
`Content-Length`) will not be counted.

---

### 2. Connection Metrics

| Metric                              | Type    | Description                        | Labels     |
|-------------------------------------|---------|------------------------------------|------------|
| `huginn_connections_total`          | Counter | Total connections established      | `protocol` |
| `huginn_connections_active`         | Gauge   | Active connections currently open  | `protocol` |
| `huginn_connections_rejected_total` | Counter | Connections rejected due to limits | `reason`   |
| `huginn_tls_connections_active`     | Gauge   | Active TLS connections             | -          |

**Labels**:

- `protocol`: Connection protocol (`http/1.1`, `h2`, `https`)
- `reason`: Rejection reason — `limit_exceeded` (active connections hit the configured maximum)

**Example queries**:

```promql
# Connection rate
rate(huginn_connections_total[5m])

# Active connections
huginn_connections_active

# Rejection rate
rate(huginn_connections_rejected_total[5m])
```

---

### 3. PROXY Protocol Metrics

Emitted when `listen.proxy_protocol.mode` is `optional` or `require`. All counters are zero when
`proxy_protocol.mode = "off"`. Both PROXY protocol v1 (text) and v2 (binary) are parsed.

| Metric                                       | Type    | Description                                                                                      | Labels   |
|----------------------------------------------|---------|--------------------------------------------------------------------------------------------------|----------|
| `huginn_proxy_protocol_accepted_total`         | Counter | Connections where the real client address was recovered from a PROXY header                       | -        |
| `huginn_proxy_protocol_passthrough_total`      | Counter | Trusted-peer connections served with the socket peer (no PROXY header, or a LOCAL/UNKNOWN command) | -        |
| `huginn_proxy_protocol_no_client_addr_total`   | Counter | Trusted-peer PROXY command with a non-IP address family (AF_UNSPEC/AF_UNIX); correlation degraded  | -        |
| `huginn_proxy_protocol_dropped_total`          | Counter | Connections dropped at the PROXY address-recovery gate                                             | `reason` |

**Labels**:

- `reason` (on `huginn_proxy_protocol_dropped_total`):
  - `untrusted_require` — `proxy_protocol.mode=require` and the peer is not in `trusted_proxies`
  - `bad_header` — signature mismatch, truncated header, or unsupported command/address family
  - `timeout` — peek or header read exceeded `listen.proxy_protocol.header_timeout_ms`

**Example queries**:

```promql
# Real-client recovery rate (connections/s where PROXY header was parsed)
rate(huginn_proxy_protocol_accepted_total[5m])

# Drop rate by reason
sum by (reason) (rate(huginn_proxy_protocol_dropped_total[5m]))

# Passthrough ratio (trusted peers with no header vs. total trusted-peer connections)
rate(huginn_proxy_protocol_passthrough_total[5m])
  / (rate(huginn_proxy_protocol_accepted_total[5m]) + rate(huginn_proxy_protocol_passthrough_total[5m]))

# Connections where a client IP was expected but not usable (degraded correlation)
rate(huginn_proxy_protocol_no_client_addr_total[5m])
```

> **Operational tip:** after enabling `proxy_protocol`, watch `huginn_proxy_protocol_accepted_total`.
> If it stays at zero while `huginn_proxy_protocol_passthrough_total` climbs, the load balancer is
> not sending headers (misconfigured edge, or wrong `trusted_proxies` CIDR). If
> `huginn_proxy_protocol_dropped_total{reason="untrusted_require"}` climbs, a peer outside the
> trusted range is reaching huginn directly. Any non-zero `huginn_proxy_protocol_no_client_addr_total`
> means a trusted proxy is sending PROXY headers without a usable client IP (non-IP address family) —
> the connection is still served on the socket peer, but the eBPF SYN fingerprint and `X-Forwarded-*`
> will not reflect the real client, so backend signature validation is degraded for those requests.

---

### 4. Request Metrics

| Metric                             | Type      | Description                                                       | Labels                                                 |
|------------------------------------|-----------|-------------------------------------------------------------------|--------------------------------------------------------|
| `huginn_entrypoint_requests_total` | Counter   | All requests arriving at the proxy, regardless of routing outcome | `method`, `status_code`, `protocol`                    |
| `huginn_requests_total`            | Counter   | Requests matched to a route and dispatched                        | `method`, `status_code`, `protocol`, `route`, `domain` |
| `huginn_requests_duration_seconds` | Histogram | Duration of routed requests                                       | `method`, `status_code`, `protocol`, `route`, `domain` |

The two request counters model the same two layers as Traefik's `entrypoint` / `router` metrics:

- **`huginn_entrypoint_requests_total`** — incremented for every HTTP request the proxy receives, including those
  rejected before routing (IP block → 403, no matching route → 404). Use this for total load and overall status-code
  distribution visible to clients.
- **`huginn_requests_total`** — incremented only when a route matched. Carries the `route` and `domain` labels so you
  can break down traffic, latency, and error rates per route *and* per domain. Unrouted requests (403, 404) are not
  counted here.

**Labels**:

- `method`: HTTP method (`GET`, `POST`, `PUT`, etc.)
- `status_code`: HTTP status code (`200`, `404`, `500`, etc.)
- `protocol`: HTTP version (`HTTP/1.1`, `HTTP/2.0`)
- `route`: Matched route prefix — only on `huginn_requests_total` (e.g., `/api`, `/`)
- `domain`: Matched domain identity — only on `huginn_requests_total`. The domain's configured `host`
  (e.g. `api.example.com`, `*.example.com`), or `_default_` for the catch-all (host-less) domain. This is the
  *configured* identity, never the client's real `Host`, so cardinality stays bounded by the number of configured
  domains; a wildcard domain collapses all its subdomains into one series. Without it, the same route prefix under two
  domains would collapse into a single series. Mirrors the `router` dimension in Traefik, and works well as a Grafana
  `$domain` template variable (`label_values(huginn_requests_total, domain)`).

**Example queries**:

```promql
# Total request rate (all traffic arriving at the proxy)
rate(huginn_entrypoint_requests_total[5m])

# Routed request rate (matched a route)
rate(huginn_requests_total[5m])

# Unrouted request rate (404 no-match + 403 blocked)
rate(huginn_entrypoint_requests_total[5m]) - rate(huginn_requests_total[5m])

# Error rate (5xx) as seen by clients
rate(huginn_entrypoint_requests_total{status_code=~"5.."}[5m])
  / rate(huginn_entrypoint_requests_total[5m])

# P95 latency (routed requests only)
histogram_quantile(0.95, rate(huginn_requests_duration_seconds_bucket[5m]))

# P99 latency
histogram_quantile(0.99, rate(huginn_requests_duration_seconds_bucket[5m]))

# Requests by route
sum by (route) (rate(huginn_requests_total[5m]))

# Requests by domain and route (distinguishes the same prefix across domains)
sum by (domain, route) (rate(huginn_requests_total[5m]))

# Requests for a single domain (e.g. a Grafana $domain template variable)
sum by (route) (rate(huginn_requests_total{domain="api.example.com"}[5m]))

# Latency by route (P95)
histogram_quantile(0.95,
  sum by (route, le) (rate(huginn_requests_duration_seconds_bucket[5m]))
)

# Error rate by route (5xx from backends)
sum by (route) (rate(huginn_requests_total{status_code=~"5.."}[5m]))
  / sum by (route) (rate(huginn_requests_total[5m]))
```

---

### 5. TLS Handshake Metrics

| Metric                                  | Type      | Description              | Labels                        |
|-----------------------------------------|-----------|--------------------------|-------------------------------|
| `huginn_tls_handshakes_total`           | Counter   | TLS handshakes completed | `tls_version`, `cipher_suite` |
| `huginn_tls_handshake_duration_seconds` | Histogram | TLS handshake duration   | `tls_version`                 |
| `huginn_tls_handshake_errors_total`     | Counter   | TLS handshake errors     | `error_type`                  |
| `huginn_timeouts_total`                 | Counter   | Timeouts by type         | `timeout_type`                |

**Labels**:

- `tls_version`: TLS version negotiated (`TLS1.2`, `TLS1.3`)
- `cipher_suite`: TLS cipher suite used (e.g., `TLS_AES_256_GCM_SHA384`)
- `error_type`: Error type (`handshake_timeout`, `invalid_certificate`, `protocol_error`, etc.)
- `timeout_type`: Timeout type (`tls_handshake`, `connection`, `idle`)

**Example queries**:

```promql
# TLS handshake rate
rate(huginn_tls_handshakes_total[5m])

# TLS version distribution
sum by (tls_version) (rate(huginn_tls_handshakes_total[5m]))

# Cipher suite distribution
sum by (cipher_suite) (rate(huginn_tls_handshakes_total[5m]))

# TLS error rate
rate(huginn_tls_handshake_errors_total[5m])

# P95 handshake duration
histogram_quantile(0.95, rate(huginn_tls_handshake_duration_seconds_bucket[5m]))
```

---

### 6. Fingerprinting Metrics

#### TLS Fingerprinting (JA4)

| Metric                                               | Type      | Description                         | Labels |
|------------------------------------------------------|-----------|-------------------------------------|--------|
| `huginn_tls_fingerprints_extracted_total`            | Counter   | TLS (JA4) fingerprints extracted    | -      |
| `huginn_tls_fingerprint_extraction_duration_seconds` | Histogram | TLS fingerprint extraction time     | -      |
| `huginn_tls_fingerprint_failures_total`              | Counter   | TLS fingerprint extraction failures | -      |

#### HTTP/2 Fingerprinting (Akamai)

| Metric                                                 | Type      | Description                            | Labels   |
|--------------------------------------------------------|-----------|----------------------------------------|----------|
| `huginn_http2_fingerprints_extracted_total`            | Counter   | HTTP/2 (Akamai) fingerprints extracted | -        |
| `huginn_http2_fingerprint_extraction_duration_seconds` | Histogram | HTTP/2 fingerprint extraction time     | -        |
| `huginn_http2_fingerprint_failures_total`              | Counter   | HTTP/2 fingerprint failures            | `reason` |

**Labels**:

- `reason`: Failure kind — `extraction_failed` (HTTP/2 connection where fingerprint could not be extracted, e.g.
  malformed frames or connection closed before SETTINGS), `not_http2` (HTTP/1.1 connection — Akamai fingerprinting does
  not apply)

#### TCP SYN Fingerprinting (p0f via eBPF)

| Metric                                        | Type      | Description                                                 | Labels   |
|-----------------------------------------------|-----------|-------------------------------------------------------------|----------|
| `huginn_tcp_syn_fingerprints_total`           | Counter   | TCP SYN fingerprint lookups (`result=hit\|miss\|malformed`) | `reason` |
| `huginn_tcp_syn_fingerprint_duration_seconds` | Histogram | BPF map lookup and parse duration                           | `reason` |
| `huginn_tcp_syn_fingerprint_failures_total`   | Counter   | Malformed BPF map entries (undecodable TCP options)         | -        |

**Labels**:

- `reason`: Lookup result — `hit` (fingerprint found and injected), `miss` (no BPF map entry — keep-alive reuse, IPv6
  peer, or stale entry), `malformed` (entry present but TCP options undecodable)

**Note**: TCP SYN fingerprinting requires the eBPF agent to be running and pinning BPF maps. The proxy reads from those
maps; this metric covers the proxy-side lookup, not the agent-side capture (see eBPF Agent Metrics for capture
counters).

#### Fingerprint Spoofing Detection

| Metric                                       | Type    | Description                                                                          | Labels   |
|----------------------------------------------|---------|--------------------------------------------------------------------------------------|----------|
| `huginn_fingerprint_spoofing_attempts_total` | Counter | Client-supplied proxy-authoritative fingerprint headers stripped (spoofing attempts) | `header` |

**Labels**:

- `header`: The header name the client attempted to supply (e.g. `x-http2-akamai`, `x-tcp-p0f`, `x-tls-ja4`)

**Note**: All eight proxy-authoritative fingerprint headers are stripped unconditionally on every request. This counter
is incremented only when the client actually sent one of those headers — i.e., when there was an active spoofing
attempt. A zero value means no clients have tried to forge fingerprints. The companion request header
`x-fingerprint-spoofing-detected` (forwarded to the backend) lists the spoofed names per-request; this metric
aggregates the same signal across requests for alerting.

**Example queries**:

```promql
# Rate of spoofing attempts (any header)
rate(huginn_fingerprint_spoofing_attempts_total[5m])

# Which fingerprint headers are being targeted
sum by (header) (rate(huginn_fingerprint_spoofing_attempts_total[5m]))

```

**Example queries (original)**:

```promql
# TLS fingerprint extraction rate
rate(huginn_tls_fingerprints_extracted_total[5m])

# HTTP/2 fingerprint extraction rate
rate(huginn_http2_fingerprints_extracted_total[5m])

# HTTP/2 fingerprint failure rate (HTTP/2 connections only)
rate(huginn_http2_fingerprint_failures_total{reason="extraction_failed"}[5m])

# HTTP/1.1 connections (no HTTP/2 fingerprint applicable)
rate(huginn_http2_fingerprint_failures_total{reason="not_http2"}[5m])

# TLS fingerprint failure rate
rate(huginn_tls_fingerprint_failures_total[5m])
  / rate(huginn_tls_fingerprints_extracted_total[5m])

# P95 extraction duration (TLS)
histogram_quantile(0.95, rate(huginn_tls_fingerprint_extraction_duration_seconds_bucket[5m]))
```

---

### 7. Backend Metrics

| Metric                            | Type      | Description                    | Labels                                                          |
|-----------------------------------|-----------|--------------------------------|-----------------------------------------------------------------|
| `huginn_backend_requests_total`   | Counter   | Requests forwarded to backends | `backend_address`, `status_code`, `protocol`, `route`, `domain` |
| `huginn_backend_errors_total`     | Counter   | Backend errors                 | `backend_address`, `error_type`, `route`, `domain`              |
| `huginn_backend_duration_seconds` | Histogram | Backend request duration       | `backend_address`, `status_code`, `protocol`, `route`, `domain` |
| `huginn_backend_selections_total` | Counter   | Backend selection events       | `backend`                                                       |

**Labels**:

- `backend`: Backend address selected at runtime (usually `host:port`, e.g., `backend-a:9000`)
- `backend_address`: Backend address (e.g., `backend-1:9000`)
- `status_code`: HTTP status code from backend
- `error_type`: Error type (`connection_refused`, `timeout`, `dns_error`, etc.)
- `protocol`: HTTP version used for backend request
- `route`: Route that triggered the backend request
- `domain`: Matched domain identity (configured `host`, or `_default_` for the catch-all — see §3)

**Example queries**:

```promql
# Backend request rate
rate(huginn_backend_requests_total[5m])

# Backend error rate (global)
sum(rate(huginn_backend_errors_total[5m]))
  / sum(rate(huginn_backend_requests_total[5m]))

# P95 backend latency
histogram_quantile(0.95, rate(huginn_backend_duration_seconds_bucket[5m]))

# Backend selection distribution
sum by (backend) (rate(huginn_backend_selections_total[5m]))

# Backend request distribution by route
sum by (backend_address, route) (rate(huginn_backend_requests_total[5m]))

# Backend requests by domain and route
sum by (domain, route) (rate(huginn_backend_requests_total[5m]))

# Backend errors by route
sum by (backend_address, route) (rate(huginn_backend_errors_total[5m]))
```

**Active health checks** (TCP or HTTP `GET` over plain `http://`, opt-in: `health_check` on a `[[backends]]` entry;
see [SETTINGS.md](SETTINGS.md)). The supervisor probes the backend; requests are short-circuited with **502** when the
upstream is marked unhealthy (`error_type` = `upstream_unhealthy` in `huginn_errors_total`).

| Metric                                   | Type    | Description                                                       | Labels              |
|------------------------------------------|---------|-------------------------------------------------------------------|---------------------|
| `huginn_health_check_probes_total`       | Counter | Probes: TCP connect or HTTP round-trip (success and failure)      | `backend`, `result` |
| `huginn_health_check_gate_rejects_total` | Counter | Client requests not forwarded because upstream is unhealthy (502) | `backend_address`   |

**Labels**:

- `backend`: Upstream `host:port` (same as backend key in the registry)
- `result`: `ok` (probe succeeded) or `fail` (timeout, refused, unexpected HTTP status, etc.)
- `backend_address`: Same as `backend` (Prometheus `backend_address` key for this counter)

**Example queries**:

```promql
# Probe success ratio per backend
sum by (backend) (rate(huginn_health_check_probes_total{result="ok"}[5m]))
  / sum by (backend) (rate(huginn_health_check_probes_total[5m]))

# 502s blocked by the health gate (per upstream)
sum by (backend_address) (rate(huginn_health_check_gate_rejects_total[5m]))

# Fail probes per backend
sum by (backend) (rate(huginn_health_check_probes_total{result="fail"}[5m]))
```

---

### 8. Rate Limiting Metrics

| Metric                             | Type    | Description                                   | Labels                        |
|------------------------------------|---------|-----------------------------------------------|-------------------------------|
| `huginn_rate_limit_requests_total` | Counter | Total requests evaluated by rate limiter      | `strategy`, `route`, `domain` |
| `huginn_rate_limit_allowed_total`  | Counter | Total requests allowed by rate limiter        | `strategy`, `route`, `domain` |
| `huginn_rate_limit_rejected_total` | Counter | Total requests rejected (429) by rate limiter | `strategy`, `route`, `domain` |

**Labels**:

- `strategy`: Rate limiting strategy (`ip`, `header`, `route`, `combined`)
- `route`: Route prefix (e.g., `/api`, `/`)
- `domain`: Matched domain identity (configured `host`, or `_default_` for the catch-all — see §3)

**Example queries**:

```promql
# Rate limit evaluation rate
rate(huginn_rate_limit_requests_total[5m])

# Rate limit rejection rate
rate(huginn_rate_limit_rejected_total[5m])

# Rate limit rejection percentage
rate(huginn_rate_limit_rejected_total[5m]) 
  / rate(huginn_rate_limit_requests_total[5m]) * 100

# Rejections by strategy
sum by (strategy) (rate(huginn_rate_limit_rejected_total[5m]))

# Rejections by route
sum by (route) (rate(huginn_rate_limit_rejected_total[5m]))

# Allow rate by strategy
sum by (strategy) (rate(huginn_rate_limit_allowed_total[5m]))
```

---

### 9. Error Metrics

| Metric                | Type    | Description          | Labels                    |
|-----------------------|---------|----------------------|---------------------------|
| `huginn_errors_total` | Counter | Total errors by type | `error_type`, `component` |

**Labels**:

- `error_type`: Error category (`config`, `tls`, `http`, `io`, `timeout`)
- `component`: Component where error occurred (`proxy`, `backend`, `fingerprint`, etc.)

**Example queries**:

```promql
# Error rate by type
sum by (error_type) (rate(huginn_errors_total[5m]))

# Total error rate
rate(huginn_errors_total[5m])
```

---

### 10. IP Filtering Metrics

| Metric                            | Type    | Description                              | Labels |
|-----------------------------------|---------|------------------------------------------|--------|
| `huginn_ip_filter_requests_total` | Counter | Total requests evaluated by IP filter    | -      |
| `huginn_ip_filter_allowed_total`  | Counter | Total requests allowed by IP filter      | -      |
| `huginn_ip_filter_denied_total`   | Counter | Total requests denied by IP filter (403) | -      |

**Example queries**:

```promql
# IP filter evaluation rate
rate(huginn_ip_filter_requests_total[5m])

# IP filter denial rate
rate(huginn_ip_filter_denied_total[5m])

# IP filter denial percentage
rate(huginn_ip_filter_denied_total[5m]) 
  / rate(huginn_ip_filter_requests_total[5m]) * 100

# Allow rate
rate(huginn_ip_filter_allowed_total[5m])
```

---

### 11. Header Manipulation Metrics

| Metric                         | Type    | Description                                  | Labels    |
|--------------------------------|---------|----------------------------------------------|-----------|
| `huginn_headers_added_total`   | Counter | Total headers added by header manipulation   | `context` |
| `huginn_headers_removed_total` | Counter | Total headers removed by header manipulation | `context` |

**Labels**:

- `context`: Context where headers were manipulated (`request`, `response`)

**Example queries**:

```promql
# Headers added rate
rate(huginn_headers_added_total[5m])

# Headers removed rate
rate(huginn_headers_removed_total[5m])

# Headers added per context
sum by (context) (rate(huginn_headers_added_total[5m]))

# Headers removed per context
sum by (context) (rate(huginn_headers_removed_total[5m]))
```

---

### 12. mTLS Metrics

| Metric                          | Type    | Description                                                       | Labels     |
|---------------------------------|---------|-------------------------------------------------------------------|------------|
| `huginn_mtls_connections_total` | Counter | Total connections with mTLS enabled (client certificate verified) | `protocol` |

**Labels**:

- `protocol`: TLS protocol version (e.g., `TLSv1.2`, `TLSv1.3`)

**Example queries**:

```promql
# mTLS connection rate
rate(huginn_mtls_connections_total[5m])

# mTLS usage percentage
rate(huginn_mtls_connections_total[5m]) 
  / rate(huginn_tls_handshakes_total[5m]) * 100

# mTLS by protocol version
sum by (protocol) (rate(huginn_mtls_connections_total[5m]))
```

**Note**:

- This metric only counts successful TLS handshakes where a client certificate was present and verified.
- mTLS verification failures are captured in `huginn_tls_handshake_errors_total`.
- When mTLS is required but client certificate is invalid/absent, the TLS handshake fails before this metric is
  recorded.

---

### 13. Config Hot Reload Metrics

| Metric                                        | Type    | Description                                  | Labels   |
|-----------------------------------------------|---------|----------------------------------------------|----------|
| `huginn_config_reload_total`                  | Counter | Config reload attempts                       | `result` |
| `huginn_config_last_reload_timestamp_seconds` | Gauge   | Unix timestamp of the last successful reload | -        |
| `huginn_config_hash`                          | Gauge   | Semantic hash of the active `DynamicConfig`  | -        |

**Labels**:

- `result`: Outcome of the reload attempt — `success` or `error`

**Notes**:

- `huginn_config_reload_total` is incremented on every reload attempt triggered by SIGHUP or filesystem watcher,
  regardless of outcome.
- `huginn_config_last_reload_timestamp_seconds` is only updated on success; use it together with
  `huginn_config_reload_total{result="error"}` to detect stuck reloads.
- Cert handling on reload is **best-effort** (Traefik-style): a domain whose certificate fails to load does
  **not** flip this counter to `error` (which tracks config parse/validation only). The reload still counts as
  `success`; the bad cert surfaces as `huginn_tls_cert_reload_total{result="error", domain="..."}` (see §13).
- `huginn_config_hash` changes whenever the deserialized `DynamicConfig` changes. It is unaffected by TOML formatting
  changes (whitespace, comments, field ordering within a table) since it hashes the parsed struct, not the raw file.

---

### 14. TLS Certificate Hot Reload Metrics

| Metric                                          | Type    | Description                                                            | Labels            |
|-------------------------------------------------|---------|------------------------------------------------------------------------|-------------------|
| `huginn_tls_cert_reload_total`                  | Counter | TLS certificate load/reload attempts per domain (includes initial load) | `result`, `domain` |
| `huginn_tls_cert_last_reload_timestamp_seconds` | Gauge   | Unix timestamp of the last successful TLS cert load or reload          | `domain`          |
| `huginn_tls_cert_hash`                          | Gauge   | FNV-1a hash of the active certificate chain for a domain (DER bytes)  | `domain`          |

**Labels**:

- `result`: Outcome of the reload attempt — `success` or `error`
- `domain`: The domain host pattern the certificate belongs to (e.g. `api.example.com`, `*.example.com`).
  The catch-all (host-less) domain reports its certs under `domain="_default_"`.

**Notes**:

- Cert loading is driven by config hot-reload (`DynamicCertResolver::update`) — each SIGHUP or config file change
  reloads all domain certs. This replaces the former per-file watcher model.
- All three metrics are **per-domain** so you can track cert rotation independently for each domain.
- Only domains that declare a certificate emit these metrics. Plain-HTTP domains and a cert-less catch-all
  produce no cert series.
- The hash and timestamp gauges are populated **at boot** for every domain with a certificate, so
  `time() - huginn_tls_cert_last_reload_timestamp_seconds{domain="..."}` is meaningful from the first scrape.
- `huginn_tls_cert_hash` hashes the certificate chain DER bytes. Private key material is intentionally excluded.
  The value is a `u64`; over the Prometheus exposition format (float64) hashes above 2^53 lose low-bit precision,
  so use `changes()` for rotation detection rather than comparing the literal value.
- Success metrics are emitted only **after** the new cert map goes live (atomic swap). A failing domain bumps
  `result="error"` and emits no success for that reload, so the hash/timestamp gauges always reflect the
  certificate actually serving traffic.
- Cert reload is **best-effort, per-domain**: one domain's failure does not abort the others. A failing domain
  keeps its *previously serving* cert (carried over from the last-good map), so its `huginn_tls_cert_hash` and
  timestamp gauges stay at their last-good value — no spurious success is emitted for a carried-over cert.
- A **cert** reload failure does *not* flip `huginn_config_reload_total` to `error` (that counter tracks config
  parse/validation only); the config reload still counts as `success` (Traefik-style best-effort, see §12).
  Alert on `huginn_tls_cert_reload_total{result="error"}` to catch cert failures.

**Example queries**:

- Detect a rotation for a domain in the last 5 minutes: `changes(huginn_tls_cert_hash{domain="api.example.com"}[5m]) > 0`
- Alert on failed reload for any domain: `rate(huginn_tls_cert_reload_total{result="error"}[5m]) > 0`
- Cert age by domain: `time() - huginn_tls_cert_last_reload_timestamp_seconds`
- Domains with a cert loaded: `count by (domain)(huginn_tls_cert_hash)`

---

### 15. Build Info

| Metric              | Type  | Description                  | Labels                    |
|---------------------|-------|------------------------------|---------------------------|
| `huginn_build_info` | Gauge | Build information (always 1) | `version`, `rust_version` |

**Labels**:

- `version`: Proxy version (e.g., `0.0.1`)
- `rust_version`: Rust version used to compile (e.g., `1.86`)

**Example queries**:

```promql
# Get current version
huginn_build_info

# Check version across multiple instances
group by (version) (huginn_build_info)
```

**Note**: This metric always has value `1` and is used to expose version information as labels.

---

## eBPF Agent Metrics

The eBPF agent (huginn-ebpf-agent) exposes a small set of metrics on its own observability server, in addition to the
same health endpoints as the proxy.

### Agent metrics

| Metric                          | Type               | Description                                                            | Labels                    |
|---------------------------------|--------------------|------------------------------------------------------------------------|---------------------------|
| `tcp_syn_captured_total`        | Observable counter | Number of TCP SYN signatures successfully captured                     | `family`                  |
| `tcp_syn_insert_failures_total` | Observable counter | Number of TCP SYN map insert failures (e.g. LRU full)                  | `family`                  |
| `tcp_syn_malformed_total`       | Observable counter | Number of malformed TCP packets (e.g. doff too short) that matched dst | `family`                  |
| `agent_up`                      | Gauge              | 1 if the agent has pinned maps and is running                          | -                         |
| `huginn_ebpf_agent_build_info`  | Gauge              | Build information (always 1)                                           | `version`, `rust_version` |

- `family` (on the three `tcp_syn_*_total` counters): `ipv4` or `ipv6`, the IP version of the
  captured/failed/malformed SYN. Sum across both for a protocol-agnostic total
  (e.g. `sum(rate(tcp_syn_captured_total[$__rate_interval]))`).

## Grafana Dashboard Suggestions

### Key Metrics to Monitor

**Overview Panel**:

- Request rate (all traffic): `rate(huginn_entrypoint_requests_total[5m])`
- Active connections: `huginn_connections_active`
- Error rate (client view):
  `rate(huginn_entrypoint_requests_total{status_code=~"5.."}[5m]) / rate(huginn_entrypoint_requests_total[5m])`
- P95 latency: `histogram_quantile(0.95, rate(huginn_requests_duration_seconds_bucket[5m]))`
- Bandwidth (MB/s): `(rate(huginn_bytes_received_total[5m]) + rate(huginn_bytes_sent_total[5m])) / 1024 / 1024`

**TLS Panel**:

- Handshake rate: `rate(huginn_tls_handshakes_total[5m])`
- TLS version distribution: `sum by (tls_version) (rate(huginn_tls_handshakes_total[5m]))`
- Handshake duration P95: `histogram_quantile(0.95, rate(huginn_tls_handshake_duration_seconds_bucket[5m]))`
- TLS error rate: `rate(huginn_tls_handshake_errors_total[5m])`

**Fingerprinting Panel**:

- TLS fingerprints/sec: `rate(huginn_tls_fingerprints_extracted_total[5m])`
- HTTP/2 fingerprints/sec: `rate(huginn_http2_fingerprints_extracted_total[5m])`
- Extraction duration P95:
  `histogram_quantile(0.95, rate(huginn_tls_fingerprint_extraction_duration_seconds_bucket[5m]))`

**Rate Limiting Panel**:

- Rate limit evaluation rate: `rate(huginn_rate_limit_requests_total[5m])`
- Rate limit rejection rate: `rate(huginn_rate_limit_rejected_total[5m])`
- Rejection percentage: `rate(huginn_rate_limit_rejected_total[5m]) / rate(huginn_rate_limit_requests_total[5m]) * 100`
- Rejections by strategy: `sum by (strategy) (rate(huginn_rate_limit_rejected_total[5m]))`

**Backend Panel**:

- Backend request rate: `sum by (backend_address) (rate(huginn_backend_requests_total[5m]))`
- Backend error rate: `sum(rate(huginn_backend_errors_total[5m])) / sum(rate(huginn_backend_requests_total[5m]))`
- Backend latency P95: `histogram_quantile(0.95, rate(huginn_backend_duration_seconds_bucket[5m]))`
- Backend throughput:
  `sum by (backend_address) (rate(huginn_backend_bytes_received_total[5m]) + rate(huginn_backend_bytes_sent_total[5m]))`
- **Health (opt-in)**: probe rate `sum by (backend) (rate(huginn_health_check_probes_total[5m]))`; fail ratio
  `rate(huginn_health_check_probes_total{result="fail"}[5m]) / rate(huginn_health_check_probes_total[5m])`;
  gate 502s `sum by (backend_address) (rate(huginn_health_check_gate_rejects_total[5m]))`

**Hot Reload Panel** (config and TLS cert grouped in one section, two parallel rows):

Config row:

- Reload success rate: `rate(huginn_config_reload_total{result="success"}[1h])`
- Reload error rate: `rate(huginn_config_reload_total{result="error"}[1h])`
- Time since last successful reload: `time() - huginn_config_last_reload_timestamp_seconds`
- Active config hash: `huginn_config_hash`

TLS certificate row (each panel aligned column-wise under its config counterpart):

- Cert reload success rate: `rate(huginn_tls_cert_reload_total{result="success"}[1h])`
- Cert reload error rate: `rate(huginn_tls_cert_reload_total{result="error"}[1h])`
- Time since last successful cert load per domain: `time() - huginn_tls_cert_last_reload_timestamp_seconds`
- Active cert hash per domain: `huginn_tls_cert_hash` (changes on every rotation; content hash for change detection)
- Detect rotation in last 5 min: `changes(huginn_tls_cert_hash[5m]) > 0`

**eBPF Agent Panel** (DaemonSet, one agent per node):

- Agent up: `agent_up`
- TCP SYN signatures captured: `tcp_syn_captured_total`
- TCP SYN insert failures: `tcp_syn_insert_failures_total`
- TCP SYN malformed: `tcp_syn_malformed_total`
- Agent version: `huginn_ebpf_agent_build_info`

---

## Future Enhancements

The following telemetry features are planned but not yet implemented:

### Metrics + Tracing for Pending Features

The following metrics are **not** implemented yet (the product may already include the related runtime behaviour):

- **Backend connection pool**: optional future gauges/counters (e.g. pool size, active/idle connections, reuse rate).
  The **connection pool to upstreams already exists** (see [SETTINGS.md](SETTINGS.md) and
  [FEATURES.md](FEATURES.md)); only dedicated Prometheus series for it are still missing.
- **Tracing**: distributed request tracing and correlation (`traceparent` propagation, proxy spans, and request ID
  correlation) is planned but not implemented yet.

---

## Grafana Dashboard

A pre-built Grafana dashboard covering all metrics in this document is available in [
`examples/grafana/dashboards/huginn-proxy.json`](examples/grafana/dashboards/huginn-proxy.json).

To run it locally alongside the proxy:

```bash
docker compose -f examples/docker-compose.observability.yml up -d
```

Then open `http://localhost:3000` and log in with **admin / huginn**. The dashboard loads automatically.

See [`examples/README.md`](examples/README.md#telemetry) for full setup instructions.