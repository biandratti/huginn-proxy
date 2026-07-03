//! PROXY protocol **v2** (binary) reader.
//!
//! The signature (`\r\n\r\n\0\r\nQUIT\n`) cannot collide with a TLS ClientHello (`0x16 0x03…`) or
//! HTTP, and the declared address-block length lets the reader consume **exactly** those bytes so
//! the stream stays aligned on the following ClientHello. Field parsing is delegated to [`ppp`];
//! this module owns only the framing and the allocation guard.

use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{ProxyProtocolError, ProxySource};

/// 12-byte v2 signature: `\r\n\r\n\0\r\nQUIT\n`.
pub const V2_SIGNATURE: [u8; 12] =
    [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

/// Fixed portion of a v2 header (signature + version/command + family/protocol + addr length).
const FIXED_LEN: usize = 16;

/// Maximum accepted `addr_len` in a v2 header.
///
/// The field is `u16` (max 65535), so an adversarial header could trigger a ~64 KB allocation per
/// connection with no real data. Real-world address blocks are at most 216 bytes (AF_UNIX). 2048 is
/// generous enough for any TLV payload a legitimate emitter would send while still bounding the
/// allocation (same cap used by rust-rpxy).
pub(super) const V2_MAX_ADDR_LEN: usize = 2048;

/// Map a `ppp` v2 header to a [`ProxySource`].
fn source_from_v2(header: &ppp::v2::Header) -> ProxySource {
    // LOCAL: the emitter provides no client address (e.g. its own health checks).
    if header.command == ppp::v2::Command::Local {
        return ProxySource::Local;
    }
    match header.addresses {
        ppp::v2::Addresses::IPv4(ref a) => {
            ProxySource::Client(SocketAddr::new(IpAddr::V4(a.source_address), a.source_port))
        }
        ppp::v2::Addresses::IPv6(ref a) => {
            ProxySource::Client(SocketAddr::new(IpAddr::V6(a.source_address), a.source_port))
        }
        // PROXY command but no usable IP source: fall back to the socket peer, but flag it.
        ppp::v2::Addresses::Unspecified | ppp::v2::Addresses::Unix(_) => ProxySource::NoClientAddr,
    }
}

/// Read and **consume** a PROXY protocol v2 header from `stream`.
///
/// Frames the read (fixed 16 bytes + the declared address length, TLVs included) so the stream is
/// left aligned on the byte that follows the header (TLS ClientHello in passthrough),
/// then delegates field parsing to [`ppp`].
///
/// Generic over `AsyncRead` so it can be unit-tested with in-memory buffers; the accept loop
/// passes a `&mut TcpStream`.
pub async fn read_proxy_header_v2<R>(stream: &mut R) -> Result<ProxySource, ProxyProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut fixed = [0u8; FIXED_LEN];
    stream
        .read_exact(&mut fixed)
        .await
        .map_err(ProxyProtocolError::Io)?;

    // The address-block length lives in bytes 14..16 regardless of the signature; cap it before
    // allocating so a garbage/hostile length cannot force a large allocation.
    let addr_len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
    if addr_len > V2_MAX_ADDR_LEN {
        return Err(ProxyProtocolError::AddrLenTooLarge(addr_len));
    }

    // Read exactly the declared address block, then hand the contiguous header to `ppp`.
    let mut buf = Vec::with_capacity(FIXED_LEN.saturating_add(addr_len));
    buf.extend_from_slice(&fixed);
    let mut addrs = vec![0u8; addr_len];
    stream
        .read_exact(&mut addrs)
        .await
        .map_err(ProxyProtocolError::Io)?;
    buf.extend_from_slice(&addrs);

    let header = ppp::v2::Header::try_from(buf.as_slice())
        .map_err(|e| ProxyProtocolError::Parse(format!("{e:?}")))?;
    Ok(source_from_v2(&header))
}
