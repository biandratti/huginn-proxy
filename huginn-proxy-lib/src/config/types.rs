use serde::Deserialize;
use std::net::SocketAddr;

/// Backend server configuration
#[derive(Debug, Deserialize, Clone)]
pub struct Backend {
    /// Backend server address (host:port format)
    /// Example: "backend-1:9000" or "192.168.1.10:8080"
    pub address: String,
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
}

/// Fingerprinting configuration
#[derive(Debug, Deserialize, Clone, Default)]
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
}

/// Logging configuration
#[derive(Debug, Deserialize, Clone, Default)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error"
    /// Default: "info"
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
    /// If no routes match, requests are distributed using round-robin
    /// Default: empty (all requests use round-robin)
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
