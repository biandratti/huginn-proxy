//! TCP probe: the simplest health check.
//!
//! Verifies that a TCP 3-way handshake completes against the backend's
//! `host:port` within `timeout`. Does **not** send any application bytes,
//! does **not** perform a TLS handshake, and does **not** validate any
//! response.
//!
//! Suitable as a default check for any backend that listens for TCP.

use std::time::Duration;
use tokio::net::TcpStream;
use tracing::trace;

/// Perform a TCP health check against `addr` (`host:port`).
/// Returns `true` if the 3-way handshake completed inside `timeout`.
pub async fn check_tcp(addr: &str, timeout: Duration) -> bool {
    let res = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .is_ok_and(|r| r.is_ok());

    trace!(
        backend = %addr,
        result = if res { "healthy" } else { "unhealthy" },
        "TCP health check"
    );

    res
}
