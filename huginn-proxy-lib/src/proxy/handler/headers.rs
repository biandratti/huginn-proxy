use huginn_net_http::AkamaiFingerprint;
use hyper::Request;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use std::net::{IpAddr, SocketAddr};

use crate::config::TrustedProxiesConfig;
use crate::fingerprinting::headers::forwarded;
use crate::security::forwarded_for_chain;

/// Convert Akamai fingerprint to HTTP header value
pub fn akamai_header_value(value: Option<&AkamaiFingerprint>) -> Option<HeaderValue> {
    value.and_then(|f| HeaderValue::from_str(&f.fingerprint).ok())
}

/// Convert TLS (JA4) fingerprint to HTTP header value
pub fn tls_header_value(value: Option<&huginn_net_tls::Ja4Payload>) -> Option<HeaderValue> {
    value.and_then(|f| HeaderValue::from_str(&f.full.to_string()).ok())
}

/// Set `X-Forwarded-For` to the chain the backend should see, ending with `peer_ip`.
///
/// The chain comes from [`forwarded_for_chain`]: an untrusted peer's inbound header is
/// discarded, a trusted proxy's is cut at the trust boundary. The result replaces every
/// inbound field line with a single comma-joined one.
///
/// When the peer is not a trusted proxy, an inbound `Forwarded` header (RFC 7239) is
/// client-supplied too and is removed. From a trusted proxy it is passed through unchanged.
pub fn set_forwarded_for(
    headers: &mut hyper::HeaderMap,
    peer_ip: IpAddr,
    trusted_proxies: &TrustedProxiesConfig,
) {
    let chain: Vec<String> = forwarded_for_chain(peer_ip, headers, trusted_proxies)
        .iter()
        .map(IpAddr::to_string)
        .collect();
    if let Ok(header_value) = HeaderValue::from_str(&chain.join(", ")) {
        headers.insert(forwarded::FOR, header_value);
    }
    if !trusted_proxies.trusts(&peer_ip) {
        headers.remove(hyper::header::FORWARDED);
    }
}

/// Add X-Forwarded-* headers to the request
///
/// This function:
/// 1. Sets X-Forwarded-For (see [`set_forwarded_for`]): the peer alone, or, behind a trusted
///    proxy, the inbound chain cut at the trust boundary plus the peer
/// 2. Sets X-Forwarded-Host from the resolved routing host
/// 3. Sets X-Forwarded-Port from the peer's port
/// 4. Sets X-Forwarded-Proto based on is_https flag
pub fn add_forwarded_headers(
    req: &mut Request<Incoming>,
    peer: SocketAddr,
    is_https: bool,
    forwarded_host: &str,
    trusted_proxies: &TrustedProxiesConfig,
) {
    set_forwarded_for(req.headers_mut(), peer.ip(), trusted_proxies);

    // X-Forwarded-Host: strip any client-supplied value first, then set it to the host the
    // proxy actually routed on. This is the resolved host from `extract_request_host`
    // (URI authority, `:authority` / absolute-form, then `Host` fallback), so it stays
    // consistent with the backend the request is forwarded to, including coalesced HTTP/2
    // connections where `:authority` differs from the connection's SNI. If the resolved host
    // is empty (e.g. an IP client that sent no authority/Host), leave the header unset.
    req.headers_mut().remove(forwarded::HOST);
    if !forwarded_host.is_empty()
        && let Ok(header_value) = HeaderValue::from_str(forwarded_host)
    {
        req.headers_mut().insert(forwarded::HOST, header_value);
    }

    // X-Forwarded-Port: Use the port from peer SocketAddr
    let port = peer.port().to_string();
    if let Ok(header_value) = HeaderValue::from_str(&port) {
        req.headers_mut().insert(forwarded::PORT, header_value);
    }

    // X-Forwarded-Proto: "https" or "http"
    let proto = if is_https { "https" } else { "http" };
    if let Ok(header_value) = HeaderValue::from_str(proto) {
        req.headers_mut().insert(forwarded::PROTO, header_value);
    }
}
