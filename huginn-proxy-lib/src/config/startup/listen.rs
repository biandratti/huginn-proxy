use serde::Deserialize;
use std::net::SocketAddr;

/// PROXY protocol v2 handling for a listener.
///
/// Honored **only** for peers in `security.trusted_proxies` (anti-spoofing). Detection of a
/// header is functional (the v2 signature cannot collide with a TLS ClientHello or HTTP), so
/// `Optional` lets one config work whether or not huginn sits behind an L4 proxy. See
/// `data/proxy-protocol.md` for the full design.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    /// Never read a PROXY header; `peer` is the socket peer (today's behavior).
    #[default]
    Off,
    /// Auto-detect: if a trusted peer sends a v2 header, use it; otherwise use the socket peer.
    /// One config works behind a proxy or directly.
    Optional,
    /// A trusted peer MUST send a valid v2 header; otherwise the connection is dropped.
    Require,
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
    /// PROXY protocol v2 handling. Only honored from peers in `security.trusted_proxies`.
    /// Default: off. Changing it alters the socket handshake, so it is static (restart to apply).
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolMode,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            addrs: vec![],
            tcp_backlog: default_tcp_backlog(),
            proxy_protocol: ProxyProtocolMode::Off,
        }
    }
}

fn default_tcp_backlog() -> i32 {
    4096
}
