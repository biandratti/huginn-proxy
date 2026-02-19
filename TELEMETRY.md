# Telemetry Documentation

> **Status**: This document covers currently implemented telemetry features.

## Overview

Huginn Proxy provides comprehensive telemetry through:

- **Prometheus Metrics** - 35 metrics covering connections, requests, TLS, fingerprinting, backends, throughput, rate limiting, IP filtering, header manipulation, and mTLS
- **Health Check Endpoints** - Kubernetes-ready health and readiness probes
- **OpenTelemetry** - Built on modern OpenTelemetry standards for future extensibility

All telemetry is exposed on a separate observability server (configurable via `telemetry.metrics_port`).

---

## Configuration

```toml
[telemetry]
metrics_port = 9090  # Port for metrics and health endpoints (default: disabled)
```

When `metrics_port` is configured, the following endpoints become available:

- `/metrics` - Prometheus metrics
- `/health` - General health check
- `/ready` - Readiness probe (Kubernetes)
- `/live` - Liveness probe (Kubernetes)

---

## Metrics Endpoint

**URL**: `http://localhost:9090/metrics`  
**Format**: Prometheus text format  
**Scraping**: Compatible with Prometheus, Grafana Agent, etc.

### Example Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'huginn-proxy'
    static_configs:
      - targets: [ 'localhost:9090' ]
    scrape_interval: 15s
```

---

## Implemented Metrics

### 1. Throughput Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `huginn_bytes_received_total` | Counter | Total bytes received from clients | `protocol` |
| `huginn_bytes_sent_total` | Counter | Total bytes sent to clients | `protocol` |
| `huginn_backend_bytes_received_total` | Counter | Total bytes received from backends | `backend_address` |
| `huginn_backend_bytes_sent_total` | Counter | Total bytes sent to backends | `backend_address` |

**Labels**:
- `protocol`: Connection protocol (`http/1.1`, `h2`, `https`)
- `backend_address`: Backend server address (e.g., `backend-1:9000`)

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

**Note**: Throughput metrics are based on `Content-Length` headers when available. Chunked transfer encoding (without `Content-Length`) will not be counted.

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
- `reason`: Rejection reason (`connection_limit`)

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

### 3. Request Metrics

| Metric                             | Type      | Description                   | Labels                                        |
|------------------------------------|-----------|-------------------------------|-----------------------------------------------|
| `huginn_requests_total`            | Counter   | Total HTTP requests processed | `method`, `status_code`, `protocol`, `route`  |
| `huginn_requests_duration_seconds` | Histogram | Request duration in seconds   | `method`, `status_code`, `protocol`, `route`  |

**Labels**:

- `method`: HTTP method (`GET`, `POST`, `PUT`, etc.)
- `status_code`: HTTP status code (`200`, `404`, `500`, etc.)
- `protocol`: HTTP version (`HTTP/1.1`, `h2`)
- `route`: Matched route prefix (e.g., `/api`, `/`)

**Example queries**:

```promql
# Request rate
rate(huginn_requests_total[5m])

# Error rate (5xx responses)
rate(huginn_requests_total{status_code=~"5.."}[5m]) 
  / rate(huginn_requests_total[5m])

# P95 latency
histogram_quantile(0.95, rate(huginn_requests_duration_seconds_bucket[5m]))

# P99 latency
histogram_quantile(0.99, rate(huginn_requests_duration_seconds_bucket[5m]))

# Requests by route
sum by (route) (rate(huginn_requests_total[5m]))

# Latency by route (P95)
histogram_quantile(0.95, 
  sum by (route, le) (rate(huginn_requests_duration_seconds_bucket[5m]))
)

# Error rate by route
sum by (route) (rate(huginn_requests_total{status_code=~"5.."}[5m]))
  / sum by (route) (rate(huginn_requests_total[5m]))
```

---

### 4. TLS Handshake Metrics

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

### 5. Fingerprinting Metrics

#### TLS Fingerprinting (JA4)

| Metric                                               | Type      | Description                         | Labels |
|------------------------------------------------------|-----------|-------------------------------------|--------|
| `huginn_tls_fingerprints_extracted_total`            | Counter   | TLS (JA4) fingerprints extracted    | -      |
| `huginn_tls_fingerprint_extraction_duration_seconds` | Histogram | TLS fingerprint extraction time     | -      |
| `huginn_tls_fingerprint_failures_total`              | Counter   | TLS fingerprint extraction failures | -      |

#### HTTP/2 Fingerprinting (Akamai)

| Metric                                                 | Type      | Description                            | Labels |
|--------------------------------------------------------|-----------|----------------------------------------|--------|
| `huginn_http2_fingerprints_extracted_total`            | Counter   | HTTP/2 (Akamai) fingerprints extracted | -      |
| `huginn_http2_fingerprint_extraction_duration_seconds` | Histogram | HTTP/2 fingerprint extraction time     | -      |
| `huginn_http2_fingerprint_failures_total`              | Counter   | HTTP/2 fingerprint failures            | -      |

**Note**: HTTP/2 fingerprint failures include HTTP/1.1 connections (expected behavior).

**Example queries**:

```promql
# TLS fingerprint extraction rate
rate(huginn_tls_fingerprints_extracted_total[5m])

# HTTP/2 fingerprint extraction rate
rate(huginn_http2_fingerprints_extracted_total[5m])

# TLS fingerprint failure rate
rate(huginn_tls_fingerprint_failures_total[5m])
  / rate(huginn_tls_fingerprints_extracted_total[5m])

# P95 extraction duration (TLS)
histogram_quantile(0.95, rate(huginn_tls_fingerprint_extraction_duration_seconds_bucket[5m]))
```

---

### 6. Backend Metrics

| Metric                            | Type      | Description                    | Labels                                                |
|-----------------------------------|-----------|--------------------------------|-------------------------------------------------------|
| `huginn_backend_requests_total`   | Counter   | Requests forwarded to backends | `backend_address`, `status_code`, `protocol`, `route` |
| `huginn_backend_errors_total`     | Counter   | Backend errors                 | `backend_address`, `error_type`, `route`              |
| `huginn_backend_duration_seconds` | Histogram | Backend request duration       | `backend_address`, `route`                            |
| `huginn_backend_selections_total` | Counter   | Backend selection events       | `backend`                                             |

**Labels**:

- `backend`: Backend name from configuration (e.g., `backend-1`)
- `backend_address`: Backend address (e.g., `backend-1:9000`)
- `status_code`: HTTP status code from backend
- `error_type`: Error type (`connection_refused`, `timeout`, `dns_error`, etc.)
- `protocol`: HTTP version used for backend request
- `route`: Route that triggered the backend request

**Example queries**:

```promql
# Backend request rate
rate(huginn_backend_requests_total[5m])

# Backend error rate
rate(huginn_backend_errors_total[5m])
  / rate(huginn_backend_requests_total[5m])

# P95 backend latency
histogram_quantile(0.95, rate(huginn_backend_duration_seconds_bucket[5m]))

# Backend distribution
sum by (backend) (rate(huginn_backend_selections_total[5m]))

# Backend requests by route
sum by (backend_address, route) (rate(huginn_backend_requests_total[5m]))

# Backend errors by route
sum by (backend_address, route) (rate(huginn_backend_errors_total[5m]))
```

---

### 7. Rate Limiting Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `huginn_rate_limit_requests_total` | Counter | Total requests evaluated by rate limiter | `strategy`, `route` |
| `huginn_rate_limit_allowed_total` | Counter | Total requests allowed by rate limiter | `strategy`, `route` |
| `huginn_rate_limit_rejected_total` | Counter | Total requests rejected (429) by rate limiter | `strategy`, `route` |

**Labels**:
- `strategy`: Rate limiting strategy (`ip`, `header`, `route`, `combined`)
- `route`: Route prefix (e.g., `/api`, `/`)

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

### 8. Error Metrics

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

### 9. IP Filtering Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `huginn_ip_filter_requests_total` | Counter | Total requests evaluated by IP filter | - |
| `huginn_ip_filter_allowed_total` | Counter | Total requests allowed by IP filter | - |
| `huginn_ip_filter_denied_total` | Counter | Total requests denied by IP filter (403) | - |

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

### 10. Header Manipulation Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `huginn_headers_added_total` | Counter | Total headers added by header manipulation | `context` |
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

### 11. mTLS Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
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
- When mTLS is required but client certificate is invalid/absent, the TLS handshake fails before this metric is recorded.

---

### 12. Build Info

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `huginn_build_info` | Gauge | Build information (always 1) | `version`, `rust_version` |

**Labels**:
- `version`: Proxy version (e.g., `0.0.1`)
- `rust_version`: Rust version used to compile (e.g., `1.85`)

**Example queries**:
```promql
# Get current version
huginn_build_info

# Check version across multiple instances
group by (version) (huginn_build_info)
```

**Note**: This metric always has value `1` and is used to expose version information as labels.

---

## Health Check Endpoints

All health endpoints return JSON responses (except `/metrics`).

### `/health` - General Health

**Purpose**: General health check  
**Status Codes**:

- `200 OK` - Process is running

**Response**:

```json
{
  "status": "healthy"
}
```

**Use case**: General monitoring, uptime checks

---

### `/ready` - Readiness Probe

**Purpose**: Kubernetes readiness probe  
**Status Codes**:

- `200 OK` - Ready to receive traffic (backends configured)
- `503 Service Unavailable` - Not ready (no backends configured)

**Response** (ready):

```json
{
  "status": "ready"
}
```

**Response** (not ready):

```json
{
  "status": "not ready",
  "reason": "no backends configured"
}
```

**Use case**: Kubernetes readiness probe, load balancer health checks

**Kubernetes configuration**:

```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 9090
  initialDelaySeconds: 5
  periodSeconds: 10
```

---

### `/live` - Liveness Probe

**Purpose**: Kubernetes liveness probe  
**Status Codes**:

- `200 OK` - Process is alive

**Response**:

```json
{
  "status": "alive"
}
```

**Use case**: Kubernetes liveness probe (detect deadlocks, crashes)

**Kubernetes configuration**:

```yaml
livenessProbe:
  httpGet:
    path: /live
    port: 9090
  initialDelaySeconds: 10
  periodSeconds: 30
```

---

## Example Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: huginn-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: huginn-proxy
  template:
    metadata:
      labels:
        app: huginn-proxy
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      containers:
        - name: huginn-proxy
          image: huginn-proxy:latest
          ports:
            - name: proxy
              containerPort: 7000
            - name: metrics
              containerPort: 9090
          livenessProbe:
            httpGet:
              path: /live
              port: 9090
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /ready
              port: 9090
            initialDelaySeconds: 5
            periodSeconds: 10
          volumeMounts:
            - name: config
              mountPath: /config.toml
              subPath: config.toml
      volumes:
        - name: config
          configMap:
            name: huginn-proxy-config
```

---

## Grafana Dashboard Suggestions

### Key Metrics to Monitor

**Overview Panel**:

- Request rate: `rate(huginn_requests_total[5m])`
- Active connections: `huginn_connections_active`
- Error rate: `rate(huginn_requests_total{status_code=~"5.."}[5m]) / rate(huginn_requests_total[5m])`
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

- Backend request rate: `sum by (backend) (rate(huginn_backend_requests_total[5m]))`
- Backend error rate: `rate(huginn_backend_errors_total[5m]) / rate(huginn_backend_requests_total[5m])`
- Backend latency P95: `histogram_quantile(0.95, rate(huginn_backend_duration_seconds_bucket[5m]))`
- Backend throughput: `sum by (backend_address) (rate(huginn_backend_bytes_received_total[5m]) + rate(huginn_backend_bytes_sent_total[5m]))`

---

## Future Enhancements

The following telemetry features are planned but not yet implemented:

### Metrics for Pending Features

The following metrics will be added when the corresponding features are implemented:

- **Connection Pooling**: Pool size, active/idle connections, reuse rate
- **Active Health Checks**: Health check status, execution count, duration
- **Circuit Breaker**: Circuit state, open/close events

### Tracing (Planned)

- Distributed tracing with Jaeger/Zipkin
- Request correlation across services
- Trace sampling

See [ROADMAP.md](ROADMAP.md) for complete list of planned features.
