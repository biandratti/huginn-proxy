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

/// Walk `X-Forwarded-For` right to left from a trusted `peer_ip`, stopping at the first
/// untrusted hop (the real client). Returns the visited hops, peer first; `None` if a visited
/// hop cannot be parsed. Entries left of the client are client-written and never read.
fn walk_trusted_hops(
    peer_ip: IpAddr,
    headers: &http::HeaderMap,
    trusted_proxies: &TrustedProxiesConfig,
) -> Option<Vec<IpAddr>> {
    let mut hops = vec![peer_ip];
    for value in headers.get_all(forwarded::FOR).iter().rev() {
        for raw in value.to_str().ok()?.rsplit(',') {
            let token = raw.trim();
            if token.is_empty() {
                continue;
            }
            let ip = parse_xff_hop(token)?;
            hops.push(ip);
            if !trusted_proxies.trusts(&ip) {
                return Some(hops);
            }
        }
    }
    Some(hops)
}

/// The client IP for rate limiting: the first untrusted hop behind a trusted peer, else the peer.
pub(crate) fn resolve_client_ip(
    peer: std::net::SocketAddr,
    headers: &http::HeaderMap,
    trusted_proxies: &TrustedProxiesConfig,
) -> String {
    let peer_ip = peer.ip();
    if !trusted_proxies.trusts(&peer_ip) {
        return peer_ip.to_string();
    }
    walk_trusted_hops(peer_ip, headers, trusted_proxies)
        .and_then(|hops| hops.last().copied())
        .filter(|ip| !trusted_proxies.trusts(ip))
        .unwrap_or(peer_ip)
        .to_string()
}

/// The `X-Forwarded-For` chain for the backend: just `peer_ip` unless the peer is trusted,
/// else the hops from the real client to `peer_ip` (unparseable: `peer_ip`).
pub fn forwarded_for_chain(
    peer_ip: IpAddr,
    headers: &http::HeaderMap,
    trusted_proxies: &TrustedProxiesConfig,
) -> Vec<IpAddr> {
    if !trusted_proxies.trusts(&peer_ip) {
        return vec![peer_ip];
    }
    let Some(mut hops) = walk_trusted_hops(peer_ip, headers, trusted_proxies) else {
        return vec![peer_ip];
    };
    hops.reverse();
    hops
}
