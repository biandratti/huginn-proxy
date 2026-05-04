use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio::signal;

use crate::error::Result;

/// Bind a TCP listener to `addr` with the given `listen(2)` backlog.
///
/// IPv6 sockets are created with `IPV6_V6ONLY = 1` so they accept only native
/// IPv6 connections. This prevents the dual-stack ambiguity where an IPv4 client
/// arrives as `::ffff:x.y.z.w` (`SocketAddr::V6`), which would cause the SYN
/// fingerprint lookup to hit the wrong eBPF map.
pub fn bind_listener(addr: SocketAddr, backlog: i32) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

pub fn register_signal(kind: signal::unix::SignalKind, name: &str) -> Result<signal::unix::Signal> {
    signal::unix::signal(kind).map_err(|e| {
        crate::error::ProxyError::Io(std::io::Error::other(format!(
            "Failed to setup {name} handler: {e}"
        )))
    })
}
