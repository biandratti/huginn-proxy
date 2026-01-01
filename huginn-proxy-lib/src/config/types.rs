use serde::Deserialize;
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
}

fn default_cert_watch_delay_secs() -> u32 {
    60
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
#[derive(Debug, Deserialize, Clone, Default)]
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
}

/// Security configuration
#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    /// Maximum number of concurrent connections allowed
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { max_connections: default_max_connections() }
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

fn default_connect_timeout() -> u64 {
    5000
}

fn default_idle_timeout() -> u64 {
    60000
}

fn default_shutdown_timeout() -> u64 {
    30
}
