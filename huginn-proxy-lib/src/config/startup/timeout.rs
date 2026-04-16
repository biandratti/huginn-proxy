use serde::Deserialize;

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

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self { enabled: true, timeout_secs: default_keep_alive_timeout() }
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

fn default_true() -> bool {
    true
}

fn default_keep_alive_timeout() -> u64 {
    60
}
