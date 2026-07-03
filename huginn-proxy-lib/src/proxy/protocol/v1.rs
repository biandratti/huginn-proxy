//! PROXY protocol **v1** (text) reader.
//!
//! The legacy `PROXY TCP4 …\r\n` line (e.g. HAProxy `send-proxy`) carries no length field, so the
//! reader consumes **byte-by-byte up to the terminating `\r\n`** (capped at 107 bytes per spec) and
//! nothing more, leaving the stream aligned on the following ClientHello. Field parsing is
//! delegated to [`ppp`]; this module owns only the framing and the length cap.

use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{ProxyProtocolError, ProxySource};

/// 6-byte v1 prefix `PROXY ` (note the trailing space).
pub const V1_PREFIX: [u8; 6] = *b"PROXY ";

/// Maximum length of a v1 text header including the terminating `\r\n` (per spec §2.1).
pub(super) const V1_MAX_LENGTH: usize = 107;

/// Map a `ppp` v1 header to a [`ProxySource`] (`UNKNOWN` → [`ProxySource::Local`]).
fn source_from_v1(header: &ppp::v1::Header) -> ProxySource {
    match header.addresses {
        ppp::v1::Addresses::Tcp4(ref a) => {
            ProxySource::Client(SocketAddr::new(IpAddr::V4(a.source_address), a.source_port))
        }
        ppp::v1::Addresses::Tcp6(ref a) => {
            ProxySource::Client(SocketAddr::new(IpAddr::V6(a.source_address), a.source_port))
        }
        // UNKNOWN is the v1 equivalent of LOCAL (health checks / non-client connections).
        ppp::v1::Addresses::Unknown => ProxySource::Local,
    }
}

/// Read and **consume** a PROXY protocol v1 (text) header from `stream`.
///
/// Reads byte-by-byte until the terminating `\r\n` so the stream is left aligned on the following
/// byte (the TLS ClientHello in the passthrough case), capped at `V1_MAX_LENGTH`, then delegates
/// field parsing to [`ppp`].
///
/// Generic over `AsyncRead` for unit testing; the accept loop passes a `&mut TcpStream`.
pub async fn read_proxy_header_v1<R>(stream: &mut R) -> Result<ProxySource, ProxyProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::with_capacity(V1_MAX_LENGTH);
    let mut byte = [0u8; 1];
    let mut found_cr = false;
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(ProxyProtocolError::Io)?;
        line.push(byte[0]);
        // Terminate on CRLF (the `\n` immediately following a `\r`).
        if found_cr && byte[0] == b'\n' {
            break;
        }
        found_cr = byte[0] == b'\r';
        if line.len() >= V1_MAX_LENGTH {
            return Err(ProxyProtocolError::V1HeaderTooLong);
        }
    }
    let header = ppp::v1::Header::try_from(line.as_slice())
        .map_err(|e| ProxyProtocolError::Parse(format!("{e:?}")))?;
    Ok(source_from_v1(&header))
}
