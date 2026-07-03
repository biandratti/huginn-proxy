//! Non-destructive version detection for an inbound connection.
//!
//! Peeks (`MSG_PEEK`) the first bytes to classify the stream as PROXY v1, v2, or neither, without
//! consuming anything — so a missing header leaves the stream intact for the TLS ClientHello.

use tokio::net::TcpStream;

use super::v1::V1_PREFIX;
use super::v2::V2_SIGNATURE;

/// Outcome of non-destructively sniffing the first bytes of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolDetection {
    /// No PROXY header — the first bytes match neither signature (e.g. a TLS ClientHello).
    None,
    /// A v1 text header (`PROXY …\r\n`).
    V1,
    /// A v2 binary header.
    V2,
}

/// Non-destructive check (`MSG_PEEK`) that classifies the connection as v1, v2, or neither.
///
/// Used before consuming so a missing header leaves the stream intact for the TLS ClientHello.
/// Loops until the version can be decided (enough bytes buffered) or the prefix already proves it
/// is **not** a PROXY header. The caller wraps this in a timeout so a slow trusted peer cannot park
/// the connection. The two signatures start with distinct bytes (`0x0D` for v2, `0x50 'P'` for v1),
/// so the classification usually resolves on the first peeked byte.
pub async fn detect_proxy_protocol(stream: &TcpStream) -> std::io::Result<ProxyProtocolDetection> {
    let sig = &V2_SIGNATURE[..];
    let pfx = &V1_PREFIX[..];
    let mut buf = [0u8; 12];
    loop {
        let n = stream.peek(&mut buf).await?;
        // EOF before any signature could be confirmed → not a PROXY header.
        if n == 0 {
            return Ok(ProxyProtocolDetection::None);
        }
        let seen = &buf[..n];

        if seen.starts_with(sig) {
            return Ok(ProxyProtocolDetection::V2);
        }
        if seen.starts_with(pfx) {
            return Ok(ProxyProtocolDetection::V1);
        }

        // Inconclusive: could the bytes seen so far still grow into either signature?
        let could_be_v2 = sig.starts_with(seen);
        let could_be_v1 = pfx.starts_with(seen);
        if !could_be_v2 && !could_be_v1 {
            return Ok(ProxyProtocolDetection::None);
        }
        // A trusted peer mid-send: small sleep before re-peeking (bounded by caller's timeout).
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}
