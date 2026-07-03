//! Source address recovery for L4-forwarded connections.
//!
//! When huginn sits behind any PROXY-protocol-capable load balancer (HAProxy, nginx stream,
//! AWS Network Load Balancer, Envoy, Kubernetes L4 ingress) the TCP socket peer is the
//! load balancer, not the client. This module parses the forwarding header prepended by the
//! load balancer to recover the original client `(src_ip, src_port)`.
//!
//! The recovered address replaces the socket peer for eBPF SYN correlation, `X-Forwarded-*`,
//! rate-limiting, IP filtering and logs. See `data/proxy-protocol.md` for the full design.
//!
//! Only the **binary encoding** is supported. The text encoding is intentionally omitted:
//! the binary signature (`\r\n\r\n\0\r\nQUIT\n`) cannot collide with a TLS ClientHello
//! (`0x16 0x03…`) or HTTP, enabling non-destructive detection via `MSG_PEEK`. The declared
//! address-block length lets the parser consume **exactly** those bytes, leaving the stream
//! aligned on the following TLS ClientHello.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;

/// 12-byte v2 signature: `\r\n\r\n\0\r\nQUIT\n`.
pub const V2_SIGNATURE: [u8; 12] =
    [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

/// Fixed portion of a v2 header (signature + version/command + family/protocol + addr length).
const FIXED_LEN: usize = 16;

/// AF_INET address block: src(4) + dst(4) + src_port(2) + dst_port(2).
const V4_ADDR_LEN: usize = 12;
/// AF_INET6 address block: src(16) + dst(16) + src_port(2) + dst_port(2).
const V6_ADDR_LEN: usize = 36;

/// Maximum accepted `addr_len` in a v2 header.
///
/// The field is `u16` (max 65535), so an adversarial header could trigger a ~64 KB allocation per
/// connection with no real data. Real-world address blocks are at most 216 bytes (AF_UNIX). 2048 is
/// generous enough for any TLV payload a legitimate emitter would send while still bounding the
/// allocation (same cap used by rust-rpxy).
const V2_MAX_ADDR_LEN: usize = 2048;

const CMD_LOCAL: u8 = 0x0;
const CMD_PROXY: u8 = 0x1;
const FAM_INET: u8 = 0x1;
const FAM_INET6: u8 = 0x2;

/// Errors from reading/parsing a PROXY v2 header.
#[derive(Debug)]
pub enum ProxyProtocolError {
    Io(std::io::Error),
    /// The first 12 bytes are not the v2 signature (e.g. a v1 text header or junk).
    BadSignature,
    /// Version nibble is not `2` (e.g. a v1 header that happened to share the prefix).
    UnsupportedVersion(u8),
    /// Command nibble is neither LOCAL (0x0) nor PROXY (0x1).
    UnsupportedCommand(u8),
    /// The declared address length is too short for the announced family.
    Truncated,
    /// The declared `addr_len` exceeds `V2_MAX_ADDR_LEN` — reject to prevent large allocation.
    AddrLenTooLarge(usize),
}

impl fmt::Display for ProxyProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyProtocolError::Io(e) => write!(f, "io error reading PROXY header: {e}"),
            ProxyProtocolError::BadSignature => write!(f, "missing PROXY v2 signature"),
            ProxyProtocolError::UnsupportedVersion(v) => {
                write!(f, "unsupported PROXY protocol version: {v}")
            }
            ProxyProtocolError::UnsupportedCommand(c) => {
                write!(f, "unsupported PROXY protocol command: {c}")
            }
            ProxyProtocolError::Truncated => write!(f, "truncated PROXY v2 address block"),
            ProxyProtocolError::AddrLenTooLarge(n) => {
                write!(f, "PROXY v2 addr_len {n} exceeds maximum {V2_MAX_ADDR_LEN}")
            }
        }
    }
}

impl std::error::Error for ProxyProtocolError {}

/// Decoded fixed header: command + family + declared address-block length.
struct FixedHeader {
    cmd: u8,
    fam: u8,
    addr_len: usize,
}

/// Parse the 16-byte fixed header. Pure (no I/O) for unit testing.
fn parse_fixed(fixed: &[u8; FIXED_LEN]) -> Result<FixedHeader, ProxyProtocolError> {
    if fixed[0..12] != V2_SIGNATURE {
        return Err(ProxyProtocolError::BadSignature);
    }
    let ver = fixed[12] >> 4;
    let cmd = fixed[12] & 0x0F;
    if ver != 2 {
        return Err(ProxyProtocolError::UnsupportedVersion(ver));
    }
    let fam = fixed[13] >> 4;
    let addr_len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
    Ok(FixedHeader { cmd, fam, addr_len })
}

/// Extract the source `SocketAddr` from a decoded fixed header + its address block. Pure.
///
/// - `Ok(Some(src))` — PROXY command with an IPv4/IPv6 source.
/// - `Ok(None)` — LOCAL command (health checks) or AF_UNSPEC/AF_UNIX → caller keeps socket peer.
fn parse_source(
    header: &FixedHeader,
    addrs: &[u8],
) -> Result<Option<SocketAddr>, ProxyProtocolError> {
    match header.cmd {
        CMD_LOCAL => Ok(None),
        CMD_PROXY => match header.fam {
            FAM_INET => {
                if addrs.len() < V4_ADDR_LEN {
                    return Err(ProxyProtocolError::Truncated);
                }
                let ip = Ipv4Addr::new(addrs[0], addrs[1], addrs[2], addrs[3]);
                let port = u16::from_be_bytes([addrs[8], addrs[9]]);
                Ok(Some(SocketAddr::V4(SocketAddrV4::new(ip, port))))
            }
            FAM_INET6 => {
                if addrs.len() < V6_ADDR_LEN {
                    return Err(ProxyProtocolError::Truncated);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&addrs[0..16]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([addrs[32], addrs[33]]);
                Ok(Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))))
            }
            // AF_UNSPEC (0x0) / AF_UNIX (0x3): no usable IP source → fall back to socket peer.
            _ => Ok(None),
        },
        other => Err(ProxyProtocolError::UnsupportedCommand(other)),
    }
}

/// Read and **consume** a PROXY protocol v2 header from `stream`.
///
/// Reads exactly the fixed header plus the declared address length (TLVs included, read and
/// ignored) so the stream is left aligned on the byte that follows the header — the TLS
/// ClientHello in the passthrough case.
///
/// Generic over `AsyncRead` so it can be unit-tested with in-memory buffers; the accept loop
/// passes a `&mut TcpStream`.
pub async fn read_proxy_header_v2<R>(
    stream: &mut R,
) -> Result<Option<SocketAddr>, ProxyProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut fixed = [0u8; FIXED_LEN];
    stream
        .read_exact(&mut fixed)
        .await
        .map_err(ProxyProtocolError::Io)?;
    let header = parse_fixed(&fixed)?;

    if header.addr_len > V2_MAX_ADDR_LEN {
        return Err(ProxyProtocolError::AddrLenTooLarge(header.addr_len));
    }
    let mut addrs = vec![0u8; header.addr_len];
    stream
        .read_exact(&mut addrs)
        .await
        .map_err(ProxyProtocolError::Io)?;
    parse_source(&header, &addrs)
}

/// Normalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to plain IPv4.
///
/// A dual-stack listener bound to `[::]` reports an incoming IPv4 connection with an
/// IPv4-mapped IPv6 peer address. The `trusted_proxies` gate matches the peer against configured
/// CIDRs, and an `IpNet::V4` entry does **not** contain an `IpAddr::V6` — so without this the
/// trust check silently fails for an IPv4 proxy on a dual-stack listener and the whole feature
/// degrades to `off`. Applied to the peer IP before the trust check. Mirrors rust-rpxy.
pub fn normalize_mapped_ipv4(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Non-destructive check (`MSG_PEEK`) for the v2 signature.
///
/// Used in `optional` mode so a missing header leaves the stream intact for TLS. Loops until 12
/// bytes are buffered or the prefix already proves it is **not** a PROXY header. The caller wraps
/// this in a timeout so a slow trusted peer cannot park the connection.
pub async fn looks_like_proxy_v2(stream: &TcpStream) -> std::io::Result<bool> {
    let mut buf = [0u8; 12];
    loop {
        let n = stream.peek(&mut buf).await?;
        if n >= 12 {
            return Ok(buf == V2_SIGNATURE);
        }
        // EOF before 12 bytes → cannot be a full header.
        if n == 0 {
            return Ok(false);
        }
        // Diverges from the signature within the bytes seen so far → not PROXY.
        if buf[..n] != V2_SIGNATURE[..n] {
            return Ok(false);
        }
        // A trusted peer mid-send: small sleep before re-peeking (bounded by caller's timeout).
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}
