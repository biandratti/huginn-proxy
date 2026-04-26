use serde::Deserialize;

use crate::error::{ProxyError, Result};

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

/// Probing strategy for backend health. Extensible; today only [`HealthCheckType::Tcp`]
/// (TCP connect) is used.
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum HealthCheckType {
    #[default]
    Tcp,
}

/// Per-backend active health check settings (opt-in: omit the table to disable).
///
/// `unhealthy_threshold` and `healthy_threshold` match
/// [`crate::backend::health_check::ConsecutiveCounter`] (consecutive failed/successful probes).
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct HealthCheckConfig {
    /// `type` in TOML/YAML (`tcp`).
    #[serde(rename = "type")]
    pub check_type: HealthCheckType,
    /// How often the supervisor runs a probe, in wall-clock seconds.
    pub interval_secs: u64,
    /// How long a single TCP probe may take before it counts as failed, in seconds.
    pub timeout_secs: u64,
    /// Consecutive failed probes before marking the backend unhealthy.
    pub unhealthy_threshold: u32,
    /// Consecutive successful probes before marking the backend healthy again.
    pub healthy_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            check_type: HealthCheckType::default(),
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        }
    }
}

impl HealthCheckConfig {
    /// Invariants for hot reload and file-based loading.
    pub fn validate(&self) -> Result<()> {
        if self.interval_secs == 0 {
            return Err(ProxyError::Config(
                "health_check.interval_secs must be greater than 0".to_string(),
            ));
        }
        if self.timeout_secs == 0 {
            return Err(ProxyError::Config(
                "health_check.timeout_secs must be greater than 0".to_string(),
            ));
        }
        if self.timeout_secs > self.interval_secs {
            return Err(ProxyError::Config(format!(
                "health_check.timeout_secs ({}) must not be greater than interval_secs ({})",
                self.timeout_secs, self.interval_secs
            )));
        }
        if self.unhealthy_threshold < 1 {
            return Err(ProxyError::Config(
                "health_check.unhealthy_threshold must be at least 1".to_string(),
            ));
        }
        if self.healthy_threshold < 1 {
            return Err(ProxyError::Config(
                "health_check.healthy_threshold must be at least 1".to_string(),
            ));
        }
        Ok(())
    }
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
    /// Optional health-check configuration; when `None`, no active probe is used for this backend
    /// (and existing routing/forwarding behavior is unchanged from pre-health-check versions).
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

/// Route configuration for path-based routing
#[derive(Debug, Deserialize, Clone, PartialEq)]
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
    /// Force a new TCP/TLS connection from the proxy to the backend for each request,
    /// bypassing the backend connection pool.
    /// Note: this does not affect the client→proxy TLS session or JA4 fingerprints,
    /// which are captured once at client connection time.
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
#[derive(Clone, Debug, Deserialize, PartialEq)]
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
