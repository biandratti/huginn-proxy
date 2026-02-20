use serde::Deserialize;

use super::headers::HeaderManipulation;
use super::security::RouteRateLimitConfig;

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
    /// Force new TCP/TLS connection for each request (bypasses connection pooling)
    /// When true, a new connection is established for every request, enabling per-request
    /// TCP and TLS fingerprinting at the cost of higher latency (extra per request)
    /// Default: false (use connection pooling for better performance)
    #[serde(default)]
    pub force_new_connection: bool,
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

/// Configuration for backend connection pool
///
/// Controls how the proxy manages connections to backend servers.
/// Connection pooling reuses TCP connections to reduce latency by avoiding
/// repeated TCP and TLS handshakes.
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

fn default_true() -> bool {
    true
}

fn default_backend_pool_idle_timeout() -> u64 {
    90
}
