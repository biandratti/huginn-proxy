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

## mTLS (Mutual TLS)

**Client certificate authentication**

When enabled, clients must present a valid certificate signed by the configured CA. Supports multiple CA certificates in a single file.

This is a global setting. Either all routes require client certs, or none do.

Limitation: No per-route mTLS configuration. No option for optional client certificates (it's either required or disabled).

## Fingerprinting

**TLS (JA4) and HTTP/2 (Akamai) fingerprints**

Passive fingerprinting extracts JA4 from the TLS ClientHello and Akamai fingerprint from HTTP/2 frames. Fingerprints are injected as headers (`x-huginn-net-ja4` and `x-huginn-net-akamai`) for backend services.

Per-route control to enable/disable fingerprinting. The extraction happens transparently with minimal overhead.

Limitation: Fingerprints are only extracted and forwarded, not validated or used for blocking. Backend services need to handle the actual fingerprint analysis and decision making.

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

**TLS handshake, HTTP read/write, and connection handling timeouts**

Multiple timeout controls to prevent resource exhaustion:
- TLS handshake timeout (default: 15s) - Maximum time for completing TLS handshake
- HTTP read timeout (default: 60s) - Maximum time to receive complete HTTP request
- HTTP write timeout (default: 60s) - Maximum time to send complete HTTP response
- Connection handling timeout (optional) - Maximum total time for entire connection lifecycle

All timeouts are independently configurable. Connection handling timeout is disabled by default.

Metrics track timeout occurrences by type (tls_handshake, connection_handling) for monitoring and alerting.

Limitation: HTTP read/write timeouts are implemented as part of connection handling timeout. Individual per-request timeouts are not supported.

## Configuration

**TOML-based config files**

Single config file for everything. Hot reload for TLS certificates, but other config changes require restart.

Limitation: No API for dynamic config changes. No config validation endpoint.

## Observability

**Prometheus metrics and health checks**

Metrics server runs on a separate port. Exposes request counters, TLS handshake metrics, rate limit metrics, and connection counts.

Health endpoints: /health (general), /ready (Kubernetes readiness), /live (Kubernetes liveness), /metrics (Prometheus).

Limitation: No distributed tracing. No request logging to files. No custom metrics.

## Timeouts

**Connect, idle, shutdown, and keep-alive**

Configurable timeouts for connection establishment, idle connections, and graceful shutdown. HTTP/1.1 keep-alive is configurable.

HTTP/2 connections are always persistent with multiplexing, so keep-alive settings don't apply there.

Limitation: No per-route timeout configuration. No TLS handshake timeout (uses default).
