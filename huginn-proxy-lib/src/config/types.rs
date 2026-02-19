use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// HTTP version preference for backend connections
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackendHttpVersion {
    Http11,
    Http2,
    /// Preserve client's HTTP version (default for HTTPS)
    Preserve,
}

/// Backend server configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Backend {
    /// Backend server address (host:port format)
    /// Example: "backend-1:9000" or "192.168.1.10:8080"
    pub address: String,
    /// HTTP version to use when connecting to this backend
    /// Options: "http11", "http2", "preserve" (default: "preserve" for HTTPS, "http11" for HTTP)
    #[serde(default)]
    pub http_version: Option<BackendHttpVersion>,
}

/// Route configuration for path-based routing
#[derive(Debug, Deserialize, Clone)]
pub struct Route {
    /// URL path prefix to match (e.g., "/api", "/static")
    /// Routes are matched in order, first match wins
    pub prefix: String,
    /// Backend address to route matching requests to
    /// Must match one of the backend addresses defined in `backends`
    pub backend: String,
    /// Enable fingerprinting for this route
    /// If true, TLS and HTTP/2 fingerprints will be injected as headers
    /// Default: true (fingerprinting enabled)
    #[serde(default = "default_true")]
    pub fingerprinting: bool,
    /// Path that will be used to replace the "prefix" part of incoming url
    /// If specified, the matched prefix will be replaced with this path before forwarding to backend
    /// Example: prefix = "/api", replace_path = "/v1"
    ///   Request: /api/users → Backend: /v1/users
    /// Example: prefix = "/api", replace_path = "" (or "/")
    ///   Request: /api/users → Backend: /users (path stripping)
    pub replace_path: Option<String>,
    /// Rate limiting configuration for this route (optional)
    /// If not specified, uses global rate limit settings
    #[serde(default)]
    pub rate_limit: Option<RouteRateLimitConfig>,
    /// Header manipulation for this route (optional)
    /// Allows adding or removing headers for specific routes
    #[serde(default)]
    pub headers: Option<HeaderManipulation>,
}

/// TLS version configuration
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
    /// TLS 1.2
    #[serde(rename = "1.2")]
    V1_2,
    /// TLS 1.3
    #[serde(rename = "1.3")]
    V1_3,
}

/// Advanced TLS configuration options
#[derive(Debug, Deserialize, Clone)]
pub struct TlsOptions {
    /// Allowed TLS versions
    /// Options: ["1.2"], ["1.3"], or ["1.2", "1.3"]
    /// Default: ["1.2", "1.3"] (all supported versions)
    #[serde(default = "default_tls_versions")]
    pub versions: Vec<TlsVersion>,
    /// Minimum TLS version
    /// Options: "1.2" or "1.3"
    /// Default: None (no minimum enforced)
    /// If specified, overrides `versions` to enforce minimum version
    #[serde(default = "default_min_version")]
    pub min_version: Option<TlsVersion>,
    /// Maximum TLS version
    /// Options: "1.2" or "1.3"
    /// Default: None (no maximum enforced)
    /// If specified, overrides `versions` to enforce maximum version
    #[serde(default = "default_max_version")]
    pub max_version: Option<TlsVersion>,
    /// Allowed cipher suites (by name)
    ///
    /// Default: uses rustls safe defaults (all supported cipher suites)
    /// See `supported_cipher_suites()` for the complete list.

    #[serde(default = "default_cipher_suites")]
    pub cipher_suites: Vec<String>,
    /// Elliptic curve preferences (key exchange groups)
    ///
    /// Specifies the order of preference for elliptic curves used in ECDHE key exchange.
    /// The first curve in the list is preferred.
    ///
    /// Default: empty (uses rustls safe defaults)
    #[serde(default = "default_curve_preferences")]
    pub curve_preferences: Vec<String>,
}

/// Client authentication mode for mTLS
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuth {
    /// Client authentication is disabled (default)
    #[default]
    Disabled,
    /// Client authentication is required
    /// Clients must present valid certificates signed by the specified CA
    Required {
        /// Path to client CA certificate file (PEM format)
        /// File must exist and be readable at startup
        /// Can contain one or more CA certificates
        ca_cert_path: String,
    },
}

/// TLS termination configuration
#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    /// Path to TLS certificate file (PEM format)
    /// File must exist and be readable at startup
    pub cert_path: String,
    /// Path to TLS private key file (PEM format)
    /// File must exist and be readable at startup
    pub key_path: String,
    /// Application-Layer Protocol Negotiation (ALPN) protocols
    /// Common values: ["h2", "http/1.1"]
    /// Default: empty (no ALPN)
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Certificate watch delay in seconds for hot reload
    #[serde(default = "default_cert_watch_delay_secs")]
    pub watch_delay_secs: u32,
    /// Controls TLS versions and cipher suites
    #[serde(default)]
    pub options: TlsOptions,
    /// Client authentication mode for mTLS (mutual TLS authentication)
    /// Default: disabled (no client authentication required)
    #[serde(default)]
    pub client_auth: ClientAuth,
    /// Session resumption configuration
    #[serde(default)]
    pub session_resumption: SessionResumptionConfig,
}

fn default_cert_watch_delay_secs() -> u32 {
    60
}

/// Session resumption configuration for TLS
#[derive(Debug, Deserialize, Clone)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct SessionResumptionConfig {
    /// Enable session resumption (default: true)
    /// When enabled, clients can reuse previous TLS sessions to reduce handshake overhead
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum number of sessions to cache (default: 256)
    /// Only applies to TLS 1.2 session ID resumption
    /// TLS 1.3 uses stateless session tickets and doesn't use this cache
    #[serde(default = "default_session_cache_size")]
    pub max_sessions: usize,
}

impl Default for SessionResumptionConfig {
    fn default() -> Self {
        Self { enabled: default_true(), max_sessions: default_session_cache_size() }
    }
}

fn default_session_cache_size() -> usize {
    256
}

/// Fingerprinting configuration
#[derive(Debug, Deserialize, Clone)]
pub struct FingerprintConfig {
    /// Enable TLS fingerprinting (JA4)
    /// Default: true
    #[serde(default = "default_true")]
    pub tls_enabled: bool,
    /// Enable HTTP/2 fingerprinting (Akamai)
    /// Note: Only works for HTTP/2 connections, not HTTP/1.x
    /// Default: true
    #[serde(default = "default_true")]
    pub http_enabled: bool,
    /// Maximum bytes to capture for HTTP/2 fingerprinting
    /// This limits the amount of data buffered for fingerprint extraction
    /// Default: 65536 (64 KB)
    #[serde(default = "default_max_capture")]
    pub max_capture: usize,
}

fn default_max_capture() -> usize {
    64 * 1024 // 64 KB
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            tls_enabled: default_true(),
            http_enabled: default_true(),
            max_capture: default_max_capture(),
        }
    }
}

/// Logging configuration
/// Controls application-level structured logging (stdout/stderr)
#[derive(Debug, Deserialize, Clone, Default)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error"
    /// Default: "info"
    /// Can be overridden at runtime via RUST_LOG environment variable
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Show module path (target) in log messages
    /// Default: false
    #[serde(default = "default_false")]
    pub show_target: bool,
}

/// Timeout configuration
#[derive(Debug, Deserialize, Clone)]
pub struct TimeoutConfig {
    /// Connection timeout in milliseconds
    /// Default: 5000 (5 seconds)
    #[serde(default = "default_connect_timeout")]
    pub connect_ms: u64,
    /// Idle connection timeout in milliseconds
    /// Default: 60000 (60 seconds)
    #[serde(default = "default_idle_timeout")]
    pub idle_ms: u64,
    /// Graceful shutdown timeout in seconds
    /// Default: 30
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_secs: u64,
    /// TLS handshake timeout in seconds
    /// Maximum time allowed for completing the TLS handshake
    /// Prevents slow clients from holding connections during handshake
    /// Default: 15 seconds
    #[serde(default = "default_tls_handshake_timeout")]
    pub tls_handshake_secs: u64,
    /// Total connection handling timeout in seconds
    /// Maximum total time for handling a complete connection lifecycle:
    /// receive request + process + send response
    /// Prevents slow clients from holding connections indefinitely
    /// Default: 300 seconds (5 minutes)
    #[serde(default = "default_connection_handling_timeout")]
    pub connection_handling_secs: u64,
    /// HTTP/1.1 keep-alive configuration
    ///
    /// Note: This configuration only applies to HTTP/1.1 connections.
    /// HTTP/2 uses persistent connections by default with native multiplexing,
    /// so keep-alive headers are not used (and are prohibited by the HTTP/2 spec).
    #[serde(default)]
    pub keep_alive: KeepAliveConfig,
}

/// HTTP/1.1 keep-alive configuration
///
/// Keep-alive allows reusing the same TCP connection for multiple HTTP requests,
/// reducing the overhead of establishing new connections for each request.
///
/// **HTTP/1.1**: Keep-alive is configurable and uses the `Connection: keep-alive` header.
///
/// **HTTP/2**: Connections are always persistent by default with native multiplexing.
/// Multiple streams can share the same connection, so keep-alive headers are not needed
/// (and are prohibited by the HTTP/2 specification).
#[derive(Debug, Deserialize, Clone)]
pub struct KeepAliveConfig {
    /// Enable HTTP/1.1 keep-alive (persistent connections)
    /// Allows reusing the same TCP connection for multiple HTTP requests
    /// Default: true
    ///
    /// Note: HTTP/2 connections are always persistent and use multiplexing,
    /// so this setting only affects HTTP/1.1 connections.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Keep-alive timeout in seconds
    /// How long to keep idle HTTP/1.1 connections open before closing them
    /// Default: 60 seconds
    ///
    /// Note: For HTTP/2, connection management is handled automatically
    /// by the protocol's multiplexing and flow control mechanisms.
    #[serde(default = "default_keep_alive_timeout")]
    pub timeout_secs: u64,
}

fn default_keep_alive_timeout() -> u64 {
    60
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self { enabled: true, timeout_secs: default_keep_alive_timeout() }
    }
}

/// Configuration for backend connection pool
///
/// Controls how the proxy manages connections to backend servers.
/// Connection pooling reuses TCP connections to reduce latency by avoiding
/// repeated TCP and TLS handshakes.
///
/// # Performance Impact
///
/// - **With pooling**: Request latency = Processing time (~10-50ms)
/// - **Without pooling**: Request latency = TCP handshake (~1-5ms) + TLS handshake (~50-200ms) + Processing (~10-50ms)
#[derive(Clone, Debug, Deserialize)]
pub struct BackendPoolConfig {
    /// Enable connection pooling globally
    /// Default: true
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Idle timeout in seconds for pooled connections
    /// How long to keep idle connections in the pool before closing them
    /// Default: 90 seconds
    #[serde(default = "default_backend_pool_idle_timeout")]
    pub idle_timeout: u64,

    /// Maximum number of idle connections to maintain per host
    /// 0 = unlimited (hyper default)
    /// Default: 0 (unlimited)
    #[serde(default)]
    pub pool_max_idle_per_host: usize,
}

impl Default for BackendPoolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            idle_timeout: default_backend_pool_idle_timeout(),
            pool_max_idle_per_host: 0,
        }
    }
}

fn default_backend_pool_idle_timeout() -> u64 {
    90
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect_ms: default_connect_timeout(),
            idle_ms: default_idle_timeout(),
            shutdown_secs: default_shutdown_timeout(),
            tls_handshake_secs: default_tls_handshake_timeout(),
            connection_handling_secs: default_connection_handling_timeout(),
            keep_alive: KeepAliveConfig::default(),
        }
    }
}

/// Security configuration
#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    /// Maximum number of concurrent connections allowed
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Security headers configuration
    #[serde(default)]
    pub headers: SecurityHeaders,
    /// IP filtering (ACL) configuration
    #[serde(default)]
    pub ip_filter: IpFilterConfig,
    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            headers: SecurityHeaders::default(),
            ip_filter: IpFilterConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

fn default_max_connections() -> usize {
    512
}

/// Telemetry configuration
/// Controls observability features: metrics, tracing, and OpenTelemetry integration
#[derive(Debug, Deserialize, Clone, Default)]
pub struct TelemetryConfig {
    /// Metrics server port (optional)
    /// If provided, starts a separate HTTP server on this port for Prometheus metrics
    /// This is the recommended production approach, similar to how Traefik handles metrics
    /// Default: None (metrics disabled)
    #[serde(default)]
    pub metrics_port: Option<u16>,
    /// OpenTelemetry internal log level
    /// Controls verbosity of OpenTelemetry SDK internal logs (not application logs)
    /// This is separate from the main application log level in [logging]
    /// Options: "trace", "debug", "info", "warn", "error"
    /// Default: "warn" (suppress informational logs from OpenTelemetry SDK)
    #[serde(default = "default_otel_log_level")]
    pub otel_log_level: String,
}

fn default_otel_log_level() -> String {
    "warn".to_string()
}

/// Main configuration structure
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Address and port to listen on
    /// Example: "0.0.0.0:7000" or "127.0.0.1:8080"
    pub listen: SocketAddr,
    /// List of backend servers for load balancing
    /// At least one backend is required
    pub backends: Vec<Backend>,
    /// Path-based routing rules (optional)
    /// If no routes match, requests return 404
    #[serde(default)]
    pub routes: Vec<Route>,
    /// Preserve the original Host header from clients when forwarding to backends
    /// When true: Backend receives the original Host header (useful for virtual hosting)
    /// When false: Backend receives the backend address as Host header (default)
    /// Default: false
    #[serde(default)]
    pub preserve_host: bool,
    /// TLS termination configuration (optional)
    /// If not provided, proxy operates in plain HTTP mode
    /// Default: None
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Fingerprinting configuration
    /// Controls which fingerprinting features are enabled
    #[serde(default)]
    pub fingerprint: FingerprintConfig,
    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Timeout configuration
    #[serde(default)]
    pub timeout: TimeoutConfig,
    /// Security configuration
    #[serde(default)]
    pub security: SecurityConfig,
    /// Telemetry configuration
    /// Controls metrics, tracing, and observability features
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// Global header manipulation (optional)
    /// Allows adding or removing headers for all routes
    #[serde(default)]
    pub headers: Option<HeaderManipulation>,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Security headers configuration
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
pub struct SecurityHeaders {
    /// Custom headers to add to all responses
    #[serde(default)]
    pub custom: Vec<CustomHeader>,
    /// HSTS (HTTP Strict Transport Security) configuration
    #[serde(default)]
    pub hsts: HstsConfig,
    /// CSP (Content Security Policy) configuration
    #[serde(default)]
    pub csp: CspConfig,
}

/// Custom header configuration
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct CustomHeader {
    /// Header name (e.g., "X-Frame-Options")
    pub name: String,
    /// Header value (e.g., "DENY")
    pub value: String,
}

/// Header manipulation for requests or responses
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
pub struct HeaderManipulationGroup {
    /// Headers to add (overwrite if exist)
    #[serde(default)]
    pub add: Vec<CustomHeader>,
    /// Headers to remove
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Header manipulation configuration
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
pub struct HeaderManipulation {
    /// Request header manipulation
    #[serde(default)]
    pub request: HeaderManipulationGroup,
    /// Response header manipulation
    #[serde(default)]
    pub response: HeaderManipulationGroup,
}

/// HSTS (HTTP Strict Transport Security) configuration
///
/// Reference: RFC 6797 - https://tools.ietf.org/html/rfc6797
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct HstsConfig {
    /// Enable HSTS (only applies to HTTPS connections)
    #[serde(default)]
    pub enabled: bool,
    /// Max age in seconds (RFC 6797 requirement)
    ///
    /// Common values:
    /// - 31536000 (1 year) - Recommended for production
    /// - 63072000 (2 years) - Very secure
    /// - 2592000 (30 days) - Minimum recommended
    /// - 300 (5 minutes) - Testing only
    ///
    /// Default: 31536000 (1 year)
    #[serde(default = "default_hsts_max_age")]
    pub max_age: u64,
    /// Include subdomains in HSTS policy (includeSubDomains directive)
    #[serde(default)]
    pub include_subdomains: bool,
    /// Add preload directive for HSTS preload list submission
    ///
    /// Warning: Only enable if you plan to submit to https://hstspreload.org/
    /// This is a permanent commitment and cannot be easily undone.
    #[serde(default)]
    pub preload: bool,
}

/// CSP (Content Security Policy) configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct CspConfig {
    /// Enable CSP
    #[serde(default)]
    pub enabled: bool,
    /// CSP policy string
    #[serde(default = "default_csp_policy")]
    pub policy: String,
}

impl Default for HstsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age: default_hsts_max_age(),
            include_subdomains: false,
            preload: false,
        }
    }
}

impl Default for CspConfig {
    fn default() -> Self {
        Self { enabled: false, policy: default_csp_policy() }
    }
}

fn default_connect_timeout() -> u64 {
    5000
}

fn default_idle_timeout() -> u64 {
    60000
}

fn default_shutdown_timeout() -> u64 {
    30
}

fn default_tls_handshake_timeout() -> u64 {
    15
}

fn default_connection_handling_timeout() -> u64 {
    300
}

fn default_hsts_max_age() -> u64 {
    31536000 // 1 year
}

fn default_csp_policy() -> String {
    "default-src 'self'".to_string()
}

/// IP filtering mode
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpFilterMode {
    /// IP filtering is disabled (allow all)
    #[default]
    Disabled,
    /// Only allow IPs in the allowlist
    Allowlist,
    /// Block IPs in the denylist
    Denylist,
}

/// IP filtering (ACL) configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct IpFilterConfig {
    /// Filtering mode
    #[serde(default)]
    pub mode: IpFilterMode,
    /// Allowlist: Only these IPs/networks are allowed (when mode = "allowlist")
    /// Supports CIDR notation: ["127.0.0.1/32", "192.168.1.0/24", "::1/128"]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_ip_networks")]
    pub allowlist: Vec<IpNet>,
    /// Denylist: These IPs/networks are blocked (when mode = "denylist")
    /// Supports CIDR notation: ["10.0.0.0/8", "172.16.0.0/12"]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_ip_networks")]
    pub denylist: Vec<IpNet>,
}

impl Default for IpFilterConfig {
    fn default() -> Self {
        Self { mode: IpFilterMode::Disabled, allowlist: vec![], denylist: vec![] }
    }
}

/// Custom deserializer for IP networks that handles parsing errors gracefully
fn deserialize_ip_networks<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    let mut networks = Vec::new();

    for s in strings {
        match s.parse::<IpNet>() {
            Ok(net) => networks.push(net),
            Err(e) => {
                return Err(serde::de::Error::custom(format!("Invalid IP network '{}': {}", s, e)));
            }
        }
    }

    Ok(networks)
}

fn default_tls_versions() -> Vec<TlsVersion> {
    vec![TlsVersion::V1_2, TlsVersion::V1_3]
}

fn default_min_version() -> Option<TlsVersion> {
    None
}

fn default_max_version() -> Option<TlsVersion> {
    None
}

fn default_cipher_suites() -> Vec<String> {
    crate::tls::cipher_suites::supported_cipher_suites()
        .into_iter()
        .map(|s| s.to_string())
        .collect()
}

fn default_curve_preferences() -> Vec<String> {
    crate::tls::curves::supported_curves()
        .into_iter()
        .map(|s| s.to_string())
        .collect()
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            versions: default_tls_versions(),
            min_version: default_min_version(),
            max_version: default_max_version(),
            cipher_suites: default_cipher_suites(),
            curve_preferences: default_curve_preferences(),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    /// Default: false
    #[serde(default)]
    pub enabled: bool,
    /// Maximum requests per second
    /// Default: 1000
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,
    /// Burst size (maximum requests in a single window)
    /// Default: 2000 (2x requests_per_second)
    #[serde(default = "default_burst")]
    pub burst: u32,
    /// Time window in seconds
    /// Default: 1
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    /// Key extraction strategy
    /// Default: "ip"
    #[serde(default = "default_limit_by")]
    pub limit_by: LimitBy,
    /// Custom header name for "header" limit_by mode
    /// Required when limit_by = "header"
    pub limit_by_header: Option<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: default_requests_per_second(),
            burst: default_burst(),
            window_seconds: default_window_seconds(),
            limit_by: default_limit_by(),
            limit_by_header: None,
        }
    }
}

/// Per-route rate limiting configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct RouteRateLimitConfig {
    /// Enable rate limiting for this route
    /// If not specified, inherits from global config
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Maximum requests per second for this route
    /// If not specified, uses global config
    pub requests_per_second: Option<u32>,
    /// Burst size for this route
    /// If not specified, uses global config
    pub burst: Option<u32>,
    /// Key extraction strategy for this route
    /// If not specified, uses global config
    pub limit_by: Option<LimitBy>,
    /// Custom header name for "header" limit_by mode
    /// If not specified, uses global config
    pub limit_by_header: Option<String>,
}

/// Rate limiting key extraction strategy
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LimitBy {
    /// Rate limit by client IP address
    /// Extracts IP from X-Forwarded-For or connection IP
    Ip,
    /// Rate limit by custom header value
    /// Requires limit_by_header to be specified
    Header,
    /// Rate limit by route path
    /// All clients share the same limit for a route
    Route,
    /// Rate limit by combination of IP and route
    /// Provides per-IP limits that are also route-specific
    Combined,
}

fn default_requests_per_second() -> u32 {
    1000
}

fn default_burst() -> u32 {
    2000
}

fn default_window_seconds() -> u64 {
    1
}

fn default_limit_by() -> LimitBy {
    LimitBy::Ip
}
