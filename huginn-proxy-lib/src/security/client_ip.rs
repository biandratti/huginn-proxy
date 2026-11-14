//! Real client IP resolution behind trusted proxies.
//!
//! `X-Forwarded-For` is only honored when the peer is in `security.trusted_proxies`. Two
//! consumers share that trust boundary:
//!
//! - `resolve_client_ip`: the address a request is attributed to (rate-limit key).
//! - [`forwarded_for_chain`]: the chain forwarded to the backend.

use crate::config::TrustedProxiesConfig;
use crate::fingerprinting::headers::forwarded;
use std::net::IpAddr;

/// Parse one `X-Forwarded-For` hop into its canonical IP.
///
/// Accepts a bare address, `[v6]`, and the `ip:port` / `[v6]:port` forms some proxies
/// append. IPv4-mapped IPv6 is folded to IPv4 so it matches IPv4 trusted CIDRs. Anything
/// else (`unknown`, obfuscated identifiers, hostnames, garbage) is `None`.
fn parse_xff_hop(token: &str) -> Option<IpAddr> {
    let ip = if let Some(rest) = token.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        if !tail.is_empty() && !is_port(tail.strip_prefix(':')?) {
            return None;
        }
        IpAddr::V6(addr.parse().ok()?)
    } else if let Some((addr, port)) = token.split_once(':')
        && !port.contains(':')
    {
        // Exactly one colon: IPv4 with a port. An unbracketed IPv6 never has just one.
        if !is_port(port) {
            return None;
        }
        IpAddr::V4(addr.parse().ok()?)
    } else {
        token.parse().ok()?
    };
    Some(ip.to_canonical())
}

/// `1*5DIGIT` that fits a `u16`.
fn is_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

/// Resolve the effective client IP for rate limiting.
///
/// When no peer is trusted (empty `cidrs` and not `insecure`), returns the TCP peer IP
/// unconditionally, this is the secure default and cannot be spoofed by a client.
///
/// When the peer is a trusted proxy, walks the inbound `X-Forwarded-For` right-to-left
/// (most-trusted first) and returns the first non-trusted IP, the real client behind
/// the load balancer. Repeated field lines are one list: the last field is the
/// rightmost hop, then each field is split on commas.
///
/// The walk fails closed. Every hop it visits was written by a trusted proxy, so a hop
/// it cannot read (non-ASCII field, or a token `parse_xff_hop` rejects) is never skipped:
/// stepping past it would land on an entry the client controls. The peer IP is used
/// instead, as it is when all entries are trusted or absent. Empty list members are
/// ignored. Entries left of the returned hop are client-supplied and are not inspected.
pub(crate) fn resolve_client_ip(
    peer: std::net::SocketAddr,
    headers: &http::HeaderMap,
    trusted_proxies: &TrustedProxiesConfig,
) -> String {
    let peer_ip = peer.ip();
    if !trusted_proxies.trusts(&peer_ip) {
        return peer_ip.to_string();
    }
    for value in headers.get_all(forwarded::FOR).iter().rev() {
        let Ok(xff_str) = value.to_str() else {
            return peer_ip.to_string();
        };
        for raw in xff_str.rsplit(',') {
            let token = raw.trim();
            if token.is_empty() {
                continue;
            }
            let Some(ip) = parse_xff_hop(token) else {
                return peer_ip.to_string();
            };
            if !trusted_proxies.trusts(&ip) {
                return ip.to_string();
            }
        }
    }
    peer_ip.to_string()
}

/// Parse the whole inbound `X-Forwarded-For` list, left to right.
///
/// Repeated field lines are one list. `None` if any field is not visible ASCII or any
/// non-empty member is not a hop [`parse_xff_hop`] accepts.
fn parse_xff_chain(headers: &http::HeaderMap) -> Option<Vec<IpAddr>> {
    let mut chain = Vec::new();
    for value in headers.get_all(forwarded::FOR) {
        for raw in value.to_str().ok()?.split(',') {
            let token = raw.trim();
            if !token.is_empty() {
                chain.push(parse_xff_hop(token)?);
            }
        }
    }
    Some(chain)
}

/// The `X-Forwarded-For` chain for the backend: just `peer_ip` unless the peer is trusted,
/// else the inbound chain plus `peer_ip`, from the real client rightwards (unparseable: `peer_ip`).
pub fn forwarded_for_chain(
    peer_ip: IpAddr,
    headers: &http::HeaderMap,
    trusted_proxies: &TrustedProxiesConfig,
) -> Vec<IpAddr> {
    if !trusted_proxies.trusts(&peer_ip) {
        return vec![peer_ip];
    }
    let Some(mut chain) = parse_xff_chain(headers) else {
        return vec![peer_ip];
    };
    chain.push(peer_ip);
    let trusted_suffix = chain
        .iter()
        .rev()
        .take_while(|ip| trusted_proxies.trusts(ip))
        .count();
    // Index of the first non-trusted hop from the right, or 0 when every hop is trusted.
    let keep_from = chain.len().saturating_sub(trusted_suffix).saturating_sub(1);
    chain.split_off(keep_from)
}
