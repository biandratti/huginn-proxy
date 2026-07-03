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
//! Both encodings are supported:
//!
//! - **v2 (binary)** — the primary path (Traefik, Envoy, AWS NLB, most modern LBs). The signature
//!   (`\r\n\r\n\0\r\nQUIT\n`) cannot collide with a TLS ClientHello (`0x16 0x03…`) or HTTP, and the
//!   declared address-block length lets the parser consume **exactly** those bytes.
//! - **v1 (text)** — the legacy `PROXY TCP4 …\r\n` line (e.g. HAProxy `send-proxy`). It carries no
//!   length field, so the reader consumes **byte-by-byte up to the terminating `\r\n`** (capped at
//!   107 bytes per spec) and nothing more.
//!
//! In both cases the stream is left aligned on the byte that follows the header — the TLS
//! ClientHello in the passthrough case — so detection via `MSG_PEEK` and consume-exactly-N keep the
//! handshake intact. The `P` (`0x50`) that starts a v1 line and the `0x0D` that starts a v2 header
//! are both distinct from a TLS record type, so a missing header is detected without consuming.
//!
//! This module owns only the **stream framing** (how many bytes to read so the ClientHello stays
//! aligned) and the anti-spoofing/DoS guards; the actual header **field parsing** is delegated to
//! the [`ppp`] crate (same parser used by the rust-rpxy reference).

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;

/// 12-byte v2 signature: `\r\n\r\n\0\r\nQUIT\n`.
pub const V2_SIGNATURE: [u8; 12] =
    [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

/// 6-byte v1 prefix `PROXY ` (note the trailing space).
pub const V1_PREFIX: [u8; 6] = *b"PROXY ";

/// Maximum length of a v1 text header including the terminating `\r\n` (per spec §2.1).
const V1_MAX_LENGTH: usize = 107;

/// Fixed portion of a v2 header (signature + version/command + family/protocol + addr length).
const FIXED_LEN: usize = 16;

/// Maximum accepted `addr_len` in a v2 header.
///
/// The field is `u16` (max 65535), so an adversarial header could trigger a ~64 KB allocation per
/// connection with no real data. Real-world address blocks are at most 216 bytes (AF_UNIX). 2048 is
/// generous enough for any TLV payload a legitimate emitter would send while still bounding the
/// allocation (same cap used by rust-rpxy).
const V2_MAX_ADDR_LEN: usize = 2048;

/// Errors from reading/parsing a PROXY protocol header.
#[derive(Debug)]
pub enum ProxyProtocolError {
    /// Underlying stream read error (including a premature EOF before the header completed).
    Io(std::io::Error),
    /// The `ppp` parser rejected the header bytes (bad signature/version/family, truncation, …).
    Parse(String),
    /// The declared v2 `addr_len` exceeds `V2_MAX_ADDR_LEN` — rejected before allocating.
    AddrLenTooLarge(usize),
    /// A v1 text header reached `V1_MAX_LENGTH` bytes without a terminating `\r\n`.
    V1HeaderTooLong,
}

impl fmt::Display for ProxyProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyProtocolError::Io(e) => write!(f, "io error reading PROXY header: {e}"),
            ProxyProtocolError::Parse(e) => write!(f, "invalid PROXY header: {e}"),
            ProxyProtocolError::AddrLenTooLarge(n) => {
                write!(f, "PROXY v2 addr_len {n} exceeds maximum {V2_MAX_ADDR_LEN}")
            }
            ProxyProtocolError::V1HeaderTooLong => {
                write!(f, "PROXY v1 header exceeds maximum {V1_MAX_LENGTH} bytes")
            }
        }
    }
}

impl std::error::Error for ProxyProtocolError {}

/// Outcome of successfully reading a PROXY header, distinguishing an expected "no client" signal
/// from an anomalous one so the caller can log/meter them differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxySource {
    /// A usable client address was recovered (PROXY command, IPv4/IPv6).
    Client(SocketAddr),
    /// LOCAL (v2) / UNKNOWN (v1): the emitter deliberately signalled no client address (e.g. its own
    /// health-check probes). Falling back to the socket peer is expected and unremarkable.
    Local,
    /// PROXY command carrying a non-IP address family (AF_UNSPEC / AF_UNIX): a client address was
    /// expected but none is usable. The caller still falls back to the socket peer, but correlation
    /// (eBPF SYN lookup, `X-Forwarded-*`) is degraded — worth a warning and a metric.
    NoClientAddr,
}

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

/// Read and **consume** a PROXY protocol v2 header from `stream`.
///
/// Frames the read (fixed 16 bytes + the declared address length, TLVs included) so the stream is
/// left aligned on the byte that follows the header — the TLS ClientHello in the passthrough case —
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
