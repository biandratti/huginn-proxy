# Features

Huginn Proxy is a reverse proxy focused on passive fingerprinting. The main goal is to extract TLS and HTTP/2 fingerprints from client connections and forward them to backend services for analysis and bot detection.

Security features like TLS termination, mTLS, rate limiting, and IP filtering are included to meet production requirements. But this is not a general-purpose reverse proxy trying to compete with Nginx or HAProxy. Some common features you might expect are missing because they don't align with the fingerprinting use case.

If you need advanced load balancing algorithms, or complex routing rules, you should use a different proxy. This one does fingerprinting well and includes enough infrastructure features to run in production, but nothing more.

## Protocol Support

**HTTP/1.1 and HTTP/2**

Both protocols are fully supported. HTTP/2 multiplexing works as expected. The proxy automatically handles protocol negotiation via ALPN when TLS is enabled.

Limitation: HTTP/3 is not supported yet.

## Load Balancing

**Round-robin algorithm**

Basic round-robin distribution across multiple backends. Works well for most use cases where backends have similar capacity.

Limitation: No health checks yet, so if a backend goes down, requests will fail until you remove it from the config. No support for least-connections or weighted algorithms.

## Path-based Routing

**Prefix matching with path manipulation**

Routes are matched by URL prefix. You can strip the prefix, replace it with a different path, or leave it unchanged. First match wins, so order matters in the config.

Examples: `/api` can be forwarded as-is, stripped to `/`, or rewritten to `/v1`. Query parameters are preserved.

Limitation: No regex support. Only simple prefix matching.

## Rate Limiting

**Token bucket algorithm**

Configurable per-route or globally. You can limit by IP, custom header, route path, or a combination. The implementation uses an atomic token bucket that refills over time.

Supports burst allowance (e.g., 100 req/s with 200 burst). Tracks limits in-memory, so restarting the proxy resets all counters.

Limitation: No distributed rate limiting across multiple proxy instances. Limits are per-process only.

## Security Headers

**HSTS, CSP, and custom headers**

HSTS is configurable with max-age, includeSubdomains, and preload directives. CSP policies are customizable. Any custom header can be added to all responses.

Headers are added on the way out, not on the way in. They apply to all routes globally.

Limitation: No per-route header configuration.

## IP Filtering

**ACL with allowlist/denylist**

Supports CIDR notation for both IPv4 and IPv6. You pick either allowlist mode (only these IPs) or denylist mode (block these IPs). Empty allowlist blocks everything, empty denylist allows everything.

Limitation: No geographic filtering or ASN-based rules.

## TLS Termination

**Server-side TLS with hot reload**

Configurable cipher suites, curve preferences, and TLS version restrictions (1.2 and 1.3 supported). ALPN works for HTTP/2 negotiation.

Certificate hot reload watches the cert files and reloads them when they change. Uses a configurable delay to avoid reloading too frequently.

Limitation: Only one certificate per proxy instance. No SNI support for serving multiple domains with different certs.

## TLS Session Resumption

**TLS 1.2 session IDs and TLS 1.3 session tickets**

Session resumption reduces handshake overhead for subsequent connections. TLS 1.2 uses server-side session ID caching (default: 256 sessions), while TLS 1.3 uses stateless session tickets.

Enabled by default. Configurable via `session_resumption.enabled` and `session_resumption.max_sessions` (for TLS 1.2 cache size).

Limitation: TLS 1.3 ticket lifetime and rotation are managed by rustls defaults. No manual control over ticket encryption keys or expiration.

## mTLS (Mutual TLS)

**Client certificate authentication**

When enabled, clients must present a valid certificate signed by the configured CA. Supports multiple CA certificates in a single file.

This is a global setting. Either all routes require client certs, or none do.

Limitation: No per-route mTLS configuration. No option for optional client certificates (it's either required or disabled).

## Fingerprinting

**TLS (JA4), HTTP/2 (Akamai), and TCP SYN (p0f-style)**

Passive fingerprinting extracts three types of signatures from client connections:

- **TLS (JA4)** - extracted from the TLS ClientHello. Injected as `x-huginn-net-ja4` (sorted, hashed), `x-huginn-net-ja4_r` (original order, hashed), `x-huginn-net-ja4_o` (sorted, raw), and `x-huginn-net-ja4_or` (original order, raw).
- **HTTP/2 (Akamai)** - extracted from HTTP/2 SETTINGS and WINDOW_UPDATE frames. Injected as `x-huginn-net-akamai`.
- **TCP SYN (p0f-style)** - extracted from the raw TCP SYN packet via an eBPF/XDP program attached to the network interface. Injected as `x-huginn-net-tcp`. Requires the `ebpf-tcp` build feature and `tcp_enabled = true` in config.

Per-route control to enable/disable TLS and HTTP/2 fingerprinting. TCP SYN fingerprinting is global (controlled by the `fingerprint.tcp_enabled` flag).

The TCP SYN signature follows the p0f format: `ip_ver:ttl:ip_olen:mss:wsize,wscale:olayout:quirks:pclass`. Quirks extracted include IP-level flags (DF, ECN, reserved bit, IP ID anomalies) and TCP-level flags (zero-seq, non-zero ACK, URG/PUSH flags, excessive window scale, timestamps).

**TCP SYN fingerprinting limitations:**

- **Linux only** - eBPF/XDP does not run on macOS or Windows. Requires kernel ≥ 5.11.
- **IPv4 only** - IPv6 connections are not captured. Transparent when a load balancer forwards internally over IPv4.
- Present on all requests of a connection (including HTTP keep-alive), since the fingerprint describes the TCP connection, not individual requests.

Limitation: Fingerprints are only extracted and forwarded, not validated or used for blocking. Backend services need to handle the actual fingerprint analysis and decision making.

## Connection Pooling

**HTTP/1.1 and HTTP/2 connection reuse**

Reuses TCP connections to backend services to reduce latency and overhead from repeated TCP and TLS handshakes. Configurable idle timeout and max idle connections per host.

Enabled by default with 90s idle timeout and 128 max idle connections per host. Can be disabled globally via `backend_pool.enabled = false`.

Per-route override available via `force_new_connection = true` to bypass pooling for specific routes (useful for TCP/TLS fingerprinting scenarios where fresh handshakes are required).

Limitation: Pooling is global or per-route only. No per-backend configuration for pool limits.

## Forwarding Headers

**X-Forwarded-* headers**

Automatically adds X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Port, and X-Forwarded-Proto. Client-provided values are overridden to prevent spoofing.

Limitation: No configurable header names. No support for Forwarded header (RFC 7239).

## Host Header Preservation

**Configurable Host header forwarding**

By default, the proxy replaces the Host header with the backend address. When preserve_host is enabled, the original Host header from the client is preserved and sent to the backend.

This is useful for virtual hosting scenarios where the backend needs to know which domain was originally requested.

Limitation: Global setting only, cannot be configured per-route.

## Granular Timeouts

**TLS handshake and connection handling timeouts**

Multiple timeout controls to prevent resource exhaustion:
- TLS handshake timeout (default: 15s) - Maximum time for completing TLS handshake
- Connection handling timeout (default: 300s/5min) - Maximum total time for entire connection lifecycle (read + process + write)

All timeouts are independently configurable.

Metrics track timeout occurrences by type (tls_handshake, connection_handling) for monitoring and alerting.

Limitation: Individual HTTP read/write timeouts are not supported. The connection_handling_secs timeout covers the entire connection lifecycle.

## Configuration

**TOML-based config files**

Single config file for everything. Hot reload for TLS certificates, but other config changes require restart.

Limitation: No API for dynamic config changes. No config validation endpoint.

## Observability

**Prometheus metrics and health checks**

Metrics server runs on a separate port (configurable via `telemetry.metrics_port`). Exposes **37 comprehensive metrics** covering connections, requests, TLS, fingerprinting, backends, throughput, rate limiting, IP filtering, header manipulation, and mTLS.

Health endpoints: `/health` (general), `/ready` (Kubernetes readiness), `/live` (Kubernetes liveness), `/metrics` (Prometheus).

**Available Metrics:**

*Connection Metrics:*
- `huginn_connections_total` - Total connections established
- `huginn_connections_active` - Active connections (gauge)
- `huginn_connections_rejected_total` - Connections rejected due to limits

*Request Metrics:*
- `huginn_requests_total` - Total HTTP requests processed
- `huginn_requests_duration_seconds` - Request duration histogram

*Throughput Metrics:*
- `huginn_bytes_received_total` - Total bytes received from clients
- `huginn_bytes_sent_total` - Total bytes sent to clients
- `huginn_backend_bytes_received_total` - Total bytes received from backends
- `huginn_backend_bytes_sent_total` - Total bytes sent to backends

*TLS Metrics:*
- `huginn_tls_connections_active` - Active TLS connections (gauge)
- `huginn_tls_handshakes_total` - Total TLS handshakes completed
- `huginn_tls_handshake_duration_seconds` - TLS handshake duration histogram
- `huginn_tls_handshake_errors_total` - TLS handshake errors

*TLS Fingerprinting (JA4):*
- `huginn_tls_fingerprints_extracted_total` - TLS fingerprints extracted
- `huginn_tls_fingerprint_extraction_duration_seconds` - Extraction duration
- `huginn_tls_fingerprint_failures_total` - Extraction failures

*HTTP/2 Fingerprinting (Akamai):*
- `huginn_http2_fingerprints_extracted_total` - HTTP/2 fingerprints extracted
- `huginn_http2_fingerprint_extraction_duration_seconds` - Extraction duration
- `huginn_http2_fingerprint_failures_total` - Extraction failures

*TCP SYN Fingerprinting (p0f-style, eBPF):*
- `huginn_tcp_syn_fingerprints_total` - TCP SYN fingerprint outcomes by result (`hit`, `miss`, `malformed`)
- `huginn_tcp_syn_fingerprint_duration_seconds` - BPF map lookup and parse duration
- `huginn_tcp_syn_fingerprint_failures_total` - Extraction failures (malformed BPF map entries)

*Backend Metrics:*
- `huginn_backend_requests_total` - Total requests forwarded to backends
- `huginn_backend_errors_total` - Backend errors
- `huginn_backend_duration_seconds` - Backend request duration histogram
- `huginn_backend_selections_total` - Backend selections (load balancing)

*Rate Limiting Metrics:*
- `huginn_rate_limit_requests_total` - Total requests evaluated by rate limiter
- `huginn_rate_limit_allowed_total` - Total requests allowed
- `huginn_rate_limit_rejected_total` - Total requests rejected (429)

*IP Filtering Metrics:*
- `huginn_ip_filter_requests_total` - Total requests evaluated by IP filter
- `huginn_ip_filter_allowed_total` - Total requests allowed
- `huginn_ip_filter_denied_total` - Total requests denied (403)

*Header Manipulation Metrics:*
- `huginn_headers_added_total` - Total headers added
- `huginn_headers_removed_total` - Total headers removed

*mTLS Metrics:*
- `huginn_mtls_connections_total` - Connections with client certificates

*Other Metrics:*
- `huginn_errors_total` - Total errors by type
- `huginn_timeouts_total` - Timeouts by type
- `huginn_build_info` - Build information (version, rust_version)

For detailed metric documentation, labels, and example queries, see [TELEMETRY.md](TELEMETRY.md).

Limitation: No distributed tracing. No request logging to files. No custom metrics.

## Timeouts

**Connect, idle, shutdown, and keep-alive**

Configurable timeouts for connection establishment, idle connections, and graceful shutdown. HTTP/1.1 keep-alive is configurable.

HTTP/2 connections are always persistent with multiplexing, so keep-alive settings don't apply there.

Limitation: No per-route timeout configuration.
