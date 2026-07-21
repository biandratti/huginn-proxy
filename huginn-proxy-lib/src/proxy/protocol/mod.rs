//! Source address recovery for L4-forwarded connections.
//!
//! When huginn sits behind any PROXY-protocol-capable load balancer (HAProxy, nginx stream,
//! AWS Network Load Balancer, Envoy, Kubernetes L4 ingress) the TCP socket peer is the
//! load balancer, not the client. This module parses the forwarding header prepended by the
//! load balancer to recover the original client `(src_ip, src_port)`.
//!
//! The recovered address replaces the socket peer for eBPF SYN correlation, `X-Forwarded-*`,
//! rate-limiting, IP filtering and logs.
//!
//! Both encodings are supported, one reader per version:
//!
//! - `v2`: the binary encoding, the primary path (Traefik, Envoy, AWS NLB, most modern LBs).
//! - `v1`: the legacy text line (e.g. HAProxy `send-proxy`).
//!
//! In both cases the stream is left aligned on the byte that follows the header (the TLS
//! ClientHello in passthrough), so detection via `MSG_PEEK` and consume-exactly-N keep
//! the handshake intact. The `P` (`0x50`) that starts a v1 line and the `0x0D` that starts a v2
//! header are both distinct from a TLS record type, so a missing header is detected without
//! consuming.
//!
//! Each version module owns only the **stream framing** (how many bytes to read so the ClientHello
//! stays aligned) and the anti-spoofing/DoS guards; the actual header **field parsing** is delegated
//! to the [`ppp`] crate (same parser used by the rust-rpxy reference).

mod detect;
mod v1;
mod v2;

pub use detect::{detect_proxy_protocol, ProxyProtocolDetection};
pub use v1::{read_proxy_header_v1, V1_PREFIX};
pub use v2::{read_proxy_header_v2, V2_SIGNATURE};

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use tracing::{error, warn};

use crate::config::{ProxyProtocolMode, TrustedProxiesConfig};

/// Errors from reading/parsing a PROXY protocol header.
#[derive(Debug)]
pub enum ProxyProtocolError {
    /// Underlying stream read error (including a premature EOF before the header completed).
    Io(std::io::Error),
    /// The `ppp` parser rejected the header bytes (bad signature/version/family, truncation, …).
    Parse(String),
    /// The declared v2 `addr_len` exceeds `V2_MAX_ADDR_LEN`, rejected before allocating.
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
                write!(f, "PROXY v2 addr_len {n} exceeds maximum {}", v2::V2_MAX_ADDR_LEN)
            }
            ProxyProtocolError::V1HeaderTooLong => {
                write!(f, "PROXY v1 header exceeds maximum {} bytes", v1::V1_MAX_LENGTH)
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
    /// (eBPF SYN lookup, `X-Forwarded-*`) is degraded; worth a warning and a metric.
    NoClientAddr,
}

/// Normalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to plain IPv4.
///
/// An IPv4 client can surface as an IPv4-mapped IPv6 address, a dual-stack listener bound to
/// `[::]`, or (more relevant here, since our listener forces `IPV6_V6ONLY`) a client declared that
/// way in a PROXY protocol header by a downstream L4 proxy. Left as-is, an `IpNet::V4` entry never
/// contains an `IpAddr::V6`, so `trusted_proxies`/`ip_filter` matches silently fail and the
/// rate-limit key splits from the equivalent native-IPv4 peer.
///
/// Used in two spots: on the socket peer before the `trusted_proxies` trust check, and on the
/// effective peer returned by `resolve_peer` (the single canonicalization point for everything
/// downstream). Mirrors rust-rpxy.
pub fn normalize_mapped_ipv4(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Diagnose a `proxy_protocol` configuration that can never trust a peer.
///
/// The PROXY header is only ever honored from an IP in `security.trusted_proxies`. When that list
/// is empty there is no peer to trust, so:
/// - `require` drops **every** connection (fail-closed), almost always a misconfiguration → `error`
/// - `optional` never parses a header, silently degrading to `off` → `warn`
///
/// `trusted_proxies` is dynamic (hot-reloadable), so this is checked both at startup and on each
/// reload. `off` is a no-op. The classification is shared with the `--validate` audit via
/// [`crate::config::audit::proxy_protocol::trust_gap`] so runtime and validation never drift.
pub(crate) fn warn_proxy_protocol_trust_gap(
    mode: ProxyProtocolMode,
    trusted_proxies: &TrustedProxiesConfig,
) {
    use crate::config::audit::proxy_protocol::{trust_gap, TrustGap};

    match trust_gap(mode, trusted_proxies.has_trust()) {
        Some(gap @ TrustGap::RequireDropsAll) => error!("{}", gap.message()),
        Some(gap @ TrustGap::OptionalDegradesToOff) => warn!("{}", gap.message()),
        None => {}
    }
}
