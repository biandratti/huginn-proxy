use serde::Deserialize;
use std::net::SocketAddr;

/// PROXY protocol (v1 and v2) handling for a listener.
///
/// Honored **only** for peers in `security.trusted_proxies` (anti-spoofing). v1 and v2 are
/// auto-detected; neither signature collides with a TLS ClientHello or HTTP, so `Optional` lets
/// one config work whether or not huginn sits behind an L4 proxy.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    /// Never read a PROXY header; `peer` is the socket peer (today's behavior).
    #[default]
    Off,
    /// Auto-detect: if a trusted peer sends a PROXY header (v1 or v2), use it; otherwise use the
    /// socket peer. One config works behind a proxy or directly.
    Optional,
    /// A trusted peer MUST send a valid PROXY header; otherwise the connection is dropped.
    Require,
}

/// PROXY protocol configuration for a listener: whether/how to honor it, and how long to wait
/// for the header. Both settings are static (restart to apply) - `mode` alters the socket
/// handshake, and `header_timeout_ms` is derived once at startup (see
/// `proxy::accept::resolve_proxy_protocol_header_timeout`).
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct ProxyProtocolConfig {
    /// PROXY protocol handling. Only honored from peers in `security.trusted_proxies`.
    /// Default: off.
    #[serde(default)]
    pub mode: ProxyProtocolMode,
    /// Timeout to read a PROXY header (v1 or v2) after a trusted peer is detected, in
    /// milliseconds. Covers both the version-sniff peek loop and the full header read.
    /// A tiny header (v1 ≤107 bytes, v2 16+≤2048 bytes) from a legitimate L4 proxy arrives in
    /// the very first write, so this stays well below a TLS handshake timeout.
    /// `0` falls back to an internal 1 s timeout (not recommended: a slow/hostile trusted peer
    /// could park a connection slot for that long). Only relevant when `mode` is `optional` or
    /// `require`. Default: 100.
    #[serde(default = "default_proxy_protocol_header_timeout_ms")]
    pub header_timeout_ms: u64,
}

impl Default for ProxyProtocolConfig {
    fn default() -> Self {
        Self {
            mode: ProxyProtocolMode::Off,
            header_timeout_ms: default_proxy_protocol_header_timeout_ms(),
        }
    }
}

/// Listener configuration, addresses and kernel socket options.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct ListenConfig {
    /// Addresses and ports to listen on. One or more entries, one per IP family.
    /// Example IPv4 only:
    /// ```text
    /// ["0.0.0.0:7000"]
    /// ```
    /// Example IPv6 only:
    /// ```text
    /// ["[::]:7000"]
    /// ```
    /// Example both:
    /// ```text
    /// ["0.0.0.0:7000", "[::]:7000"]
    /// ```
    pub addrs: Vec<SocketAddr>,
    /// `listen(2)` backlog, length of the pending-connection queue per listener socket.
    /// Raise this under high connection rates to avoid the kernel silently dropping SYNs before
    /// `accept(2)` is called. The kernel clamps the value to `net.core.somaxconn`.
    /// Passed directly to `listen(2)`. Default: 4096 (matches modern Linux SOMAXCONN)
    #[serde(default = "default_tcp_backlog")]
    pub tcp_backlog: i32,
    /// PROXY protocol (v1 and v2) handling: mode and header read timeout. See
    /// [`ProxyProtocolConfig`].
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolConfig,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            addrs: vec![],
            tcp_backlog: default_tcp_backlog(),
            proxy_protocol: ProxyProtocolConfig::default(),
        }
    }
}

fn default_tcp_backlog() -> i32 {
    4096
}

fn default_proxy_protocol_header_timeout_ms() -> u64 {
    100
}
