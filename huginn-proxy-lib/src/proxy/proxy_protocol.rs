//! Minimal PROXY protocol **v2** reader.
//!
//! Recovers the original client `(src_ip, src_port)` when huginn runs behind an L4 proxy that
//! does TLS passthrough (e.g. Traefik `IngressRouteTCP` with `proxyProtocol.version: 2`). The
//! parsed source address replaces the socket peer for the eBPF SYN lookup, `X-Forwarded-*`,
//! rate-limiting, IP filtering and logs. See `data/proxy-protocol.md` for the design.
//!
//! v1 (text) is intentionally **not** supported: v2 is a fixed binary layout, so we can consume
//! **exactly** the header length and leave the stream aligned on the following TLS ClientHello.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

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

    let mut addrs = vec![0u8; header.addr_len];
    stream
        .read_exact(&mut addrs)
        .await
        .map_err(ProxyProtocolError::Io)?;
    parse_source(&header, &addrs)
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
        // A trusted peer mid-send: yield and re-peek (bounded by the caller's timeout).
        tokio::task::yield_now().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Build a v2 header: signature + ver/cmd + fam/proto + len + address block.
    fn build_header(cmd: u8, fam: u8, addrs: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&V2_SIGNATURE);
        buf.push((2 << 4) | (cmd & 0x0F));
        buf.push((fam << 4) | 0x1); // protocol = STREAM (0x1)
        buf.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
        buf.extend_from_slice(addrs);
        buf
    }

    fn v4_block(src: [u8; 4], src_port: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&src); // src
        b.extend_from_slice(&[10, 0, 0, 1]); // dst (ignored)
        b.extend_from_slice(&src_port.to_be_bytes()); // src port
        b.extend_from_slice(&8443u16.to_be_bytes()); // dst port (ignored)
        b
    }

    fn v6_block(src: [u8; 16], src_port: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&src); // src
        b.extend_from_slice(&[0u8; 16]); // dst (ignored)
        b.extend_from_slice(&src_port.to_be_bytes()); // src port
        b.extend_from_slice(&8443u16.to_be_bytes()); // dst port (ignored)
        b
    }

    #[tokio::test]
    async fn parses_valid_ipv4() -> TestResult {
        let header = build_header(CMD_PROXY, FAM_INET, &v4_block([192, 168, 1, 100], 51234));
        let mut cursor = Cursor::new(header);
        let src = read_proxy_header_v2(&mut cursor).await?;
        assert_eq!(src, Some("192.168.1.100:51234".parse()?));
        Ok(())
    }

    #[tokio::test]
    async fn parses_valid_ipv6() -> TestResult {
        let octets = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        let header = build_header(CMD_PROXY, FAM_INET6, &v6_block(octets, 40000));
        let mut cursor = Cursor::new(header);
        let src = read_proxy_header_v2(&mut cursor).await?;
        assert_eq!(src, Some("[2001:db8::1]:40000".parse()?));
        Ok(())
    }

    #[tokio::test]
    async fn local_command_returns_none() -> TestResult {
        // LOCAL command (health checks): no address block.
        let header = build_header(CMD_LOCAL, 0x0, &[]);
        let mut cursor = Cursor::new(header);
        let src = read_proxy_header_v2(&mut cursor).await?;
        assert_eq!(src, None);
        Ok(())
    }

    #[tokio::test]
    async fn af_unspec_falls_back() -> TestResult {
        // PROXY command but AF_UNSPEC family → no usable source.
        let header = build_header(CMD_PROXY, 0x0, &[]);
        let mut cursor = Cursor::new(header);
        let src = read_proxy_header_v2(&mut cursor).await?;
        assert_eq!(src, None);
        Ok(())
    }

    #[tokio::test]
    async fn bad_signature_is_rejected() {
        let mut bytes = vec![0u8; FIXED_LEN];
        bytes[0] = 0xFF; // corrupt the signature
        let mut cursor = Cursor::new(bytes);
        let result = read_proxy_header_v2(&mut cursor).await;
        assert!(matches!(result, Err(ProxyProtocolError::BadSignature)), "got {result:?}");
    }

    #[tokio::test]
    async fn v1_text_header_is_unsupported_version() {
        // A v1 text header ("PROXY TCP4 ...") does not match the binary signature.
        let mut cursor = Cursor::new(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n".to_vec());
        let result = read_proxy_header_v2(&mut cursor).await;
        assert!(matches!(result, Err(ProxyProtocolError::BadSignature)), "got {result:?}");
    }

    #[tokio::test]
    async fn truncated_address_block_errors() {
        // Announce AF_INET but provide fewer than 12 address bytes.
        let header = build_header(CMD_PROXY, FAM_INET, &[1, 2, 3, 4]);
        let mut cursor = Cursor::new(header);
        let result = read_proxy_header_v2(&mut cursor).await;
        assert!(matches!(result, Err(ProxyProtocolError::Truncated)), "got {result:?}");
    }

    #[tokio::test]
    async fn consumes_exactly_header_leaving_clienthello() -> TestResult {
        // Header followed by a synthetic TLS ClientHello prefix. After parsing, the next bytes
        // read must equal the ClientHello untouched (alignment proof).
        let client_hello = [0x16u8, 0x03, 0x01, 0x00, 0x2a, 0xde, 0xad, 0xbe, 0xef];
        let mut stream = build_header(CMD_PROXY, FAM_INET, &v4_block([203, 0, 113, 5], 12345));
        stream.extend_from_slice(&client_hello);

        let mut cursor = Cursor::new(stream);
        let src = read_proxy_header_v2(&mut cursor).await?;
        assert_eq!(src, Some("203.0.113.5:12345".parse()?));

        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).await?;
        assert_eq!(rest, client_hello, "ClientHello bytes must remain after the header");
        Ok(())
    }

    #[tokio::test]
    async fn ignores_trailing_tlvs_but_consumes_them() -> TestResult {
        // Address block longer than the minimum (TLVs appended) must be fully consumed.
        let mut block = v4_block([10, 1, 2, 3], 5555);
        block.extend_from_slice(&[0x03, 0x00, 0x02, 0xAA, 0xBB]); // a fake TLV
        let client_hello = [0x16u8, 0x03, 0x03];
        let mut stream = build_header(CMD_PROXY, FAM_INET, &block);
        stream.extend_from_slice(&client_hello);

        let mut cursor = Cursor::new(stream);
        let src = read_proxy_header_v2(&mut cursor).await?;
        assert_eq!(src, Some("10.1.2.3:5555".parse()?));

        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).await?;
        assert_eq!(rest, client_hello);
        Ok(())
    }
}
