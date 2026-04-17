use serde::Deserialize;

/// Timeout configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct TimeoutConfig {
    /// TCP connect timeout to upstream backends in milliseconds.
    /// If absent, no connect timeout is applied.
    #[serde(default)]
    pub upstream_connect_ms: Option<u64>,
    /// Idle connection timeout for inbound client connections in milliseconds.
    /// Applied as HTTP/1.1 `header_read_timeout` and HTTP/2 keep-alive interval.
    /// Default: 60000 (60 seconds)
    #[serde(default = "default_proxy_idle_ms")]
    pub proxy_idle_ms: u64,
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

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            upstream_connect_ms: None,
            proxy_idle_ms: default_proxy_idle_ms(),
            shutdown_secs: default_shutdown_timeout(),
            tls_handshake_secs: default_tls_handshake_timeout(),
            connection_handling_secs: default_connection_handling_timeout(),
            keep_alive: KeepAliveConfig::default(),
        }
    }
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
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct KeepAliveConfig {
    /// Enable HTTP/1.1 keep-alive (persistent connections)
    /// Allows reusing the same TCP connection for multiple HTTP requests
    /// Default: true
    ///
    /// Note: HTTP/2 connections are always persistent and use multiplexing,
    /// so this setting only affects HTTP/1.1 connections.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// TCP keep-alive interval for upstream (proxy → backend) connections, in seconds.
    /// Maps to rpxy's `upstream_idle_timeout`: sets how often TCP keepalive packets are sent
    /// to detect dead backend connections.
    /// Default: 60 seconds
    #[serde(default = "default_upstream_idle_timeout")]
    pub upstream_idle_timeout: u64,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self { enabled: true, upstream_idle_timeout: default_upstream_idle_timeout() }
    }
}

fn default_proxy_idle_ms() -> u64 {
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

fn default_true() -> bool {
    true
}

fn default_upstream_idle_timeout() -> u64 {
    60
}
