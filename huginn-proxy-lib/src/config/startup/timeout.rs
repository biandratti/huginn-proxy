use serde::{Deserialize, Serialize};

/// Timeout configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TimeoutConfig {
    /// TCP connect timeout to upstream backends in milliseconds.
    /// If absent, no connect timeout is applied.
    #[serde(default)]
    pub upstream_connect_ms: Option<u64>,
    /// Idle connection timeout for inbound client connections in milliseconds.
    /// Applied as HTTP/1.1 `header_read_timeout` and HTTP/2 keep-alive interval.
    /// Default: 20000 (20 seconds)
    #[serde(default = "default_proxy_idle_ms")]
    pub proxy_idle_ms: u64,
    /// Seconds to fail `/ready` while still accepting (phase 1). `0` = fail
    /// readiness and stop accepting together (historical behaviour).
    /// Default: 0
    #[serde(default)]
    pub drain_delay_secs: u64,
    /// Graceful shutdown timeout in seconds
    /// Default: 30
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_secs: u64,
    /// TLS handshake timeout in seconds
    /// Maximum time allowed for completing the TLS handshake
    /// Prevents slow clients from holding connections during handshake
    /// Default: 5 seconds
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
            drain_delay_secs: 0,
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
#[serde(deny_unknown_fields)]
pub struct KeepAliveConfig {
    /// Enable HTTP/1.1 keep-alive (persistent connections)
    /// Allows reusing the same TCP connection for multiple HTTP requests
    /// Default: true
    ///
    /// Note: HTTP/2 connections are always persistent and use multiplexing.
    /// When `false`, HTTP/2 PING and TCP keep-alive are also disabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Idle seconds before TCP keep-alive probes on upstream (proxy → backend) connections.
    /// Maps to rpxy's `upstream_idle_timeout`.
    /// Default: 20 seconds
    #[serde(default = "default_upstream_idle_timeout")]
    pub upstream_idle_timeout: u64,
    /// Idle seconds before TCP keep-alive probes on client connections.
    /// Default: 20 seconds
    #[serde(default = "default_client_tcp_idle_secs")]
    pub client_tcp_idle_secs: u64,
    /// Seconds between TCP keep-alive probes, on client and upstream connections.
    /// Default: 10 seconds
    #[serde(default = "default_tcp_interval_secs")]
    pub tcp_interval_secs: u64,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            upstream_idle_timeout: default_upstream_idle_timeout(),
            client_tcp_idle_secs: default_client_tcp_idle_secs(),
            tcp_interval_secs: default_tcp_interval_secs(),
        }
    }
}
fn default_proxy_idle_ms() -> u64 {
    20000
}

fn default_shutdown_timeout() -> u64 {
    30
}

fn default_tls_handshake_timeout() -> u64 {
    5
}

fn default_connection_handling_timeout() -> u64 {
    300
}

fn default_true() -> bool {
    true
}

fn default_upstream_idle_timeout() -> u64 {
    20
}

fn default_client_tcp_idle_secs() -> u64 {
    20
}

fn default_tcp_interval_secs() -> u64 {
    10
}

/// Allowlisted effective-config view of [`TimeoutConfig`]. Field names are the JSON keys.
#[derive(Serialize)]
pub(crate) struct TimeoutView {
    upstream_connect_ms: Option<u64>,
    proxy_idle_ms: u64,
    drain_delay_secs: u64,
    shutdown_secs: u64,
    tls_handshake_secs: u64,
    connection_handling_secs: u64,
    keep_alive: KeepAliveView,
}

#[derive(Serialize)]
struct KeepAliveView {
    enabled: bool,
    upstream_idle_timeout: u64,
    client_tcp_idle_secs: u64,
    tcp_interval_secs: u64,
}

impl TimeoutConfig {
    pub(crate) fn effective_view(&self) -> TimeoutView {
        TimeoutView {
            upstream_connect_ms: self.upstream_connect_ms,
            proxy_idle_ms: self.proxy_idle_ms,
            drain_delay_secs: self.drain_delay_secs,
            shutdown_secs: self.shutdown_secs,
            tls_handshake_secs: self.tls_handshake_secs,
            connection_handling_secs: self.connection_handling_secs,
            keep_alive: KeepAliveView {
                enabled: self.keep_alive.enabled,
                upstream_idle_timeout: self.keep_alive.upstream_idle_timeout,
                client_tcp_idle_secs: self.keep_alive.client_tcp_idle_secs,
                tcp_interval_secs: self.keep_alive.tcp_interval_secs,
            },
        }
    }
}
