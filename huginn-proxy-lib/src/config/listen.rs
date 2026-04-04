use serde::Deserialize;
use std::net::SocketAddr;

/// Listener configuration — addresses and kernel socket options.
#[derive(Debug, Deserialize, Clone)]
pub struct ListenConfig {
    /// Addresses and ports to listen on. One or more entries, one per IP family.
    /// Example IPv4 only: ["0.0.0.0:7000"]
    /// Example IPv6 only: ["[::]:7000"]
    /// Example both:      ["0.0.0.0:7000", "[::]:7000"]
    pub addrs: Vec<SocketAddr>,
    /// `listen(2)` backlog — length of the pending-connection queue per listener socket.
    /// Raise this under high connection rates to avoid the kernel silently dropping SYNs before
    /// `accept(2)` is called. The kernel clamps the value to `net.core.somaxconn`.
    /// Passed directly to `listen(2)`. Default: 4096 (matches modern Linux SOMAXCONN)
    #[serde(default = "default_tcp_backlog")]
    pub tcp_backlog: i32,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self { addrs: vec![], tcp_backlog: default_tcp_backlog() }
    }
}

fn default_tcp_backlog() -> i32 {
    4096
}
