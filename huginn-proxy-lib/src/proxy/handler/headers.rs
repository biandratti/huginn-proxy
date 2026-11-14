use huginn_net_http::AkamaiFingerprint;
use hyper::Request;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use std::net::{IpAddr, SocketAddr};

use crate::fingerprinting::headers::forwarded;

/// Convert Akamai fingerprint to HTTP header value
pub fn akamai_header_value(value: Option<&AkamaiFingerprint>) -> Option<HeaderValue> {
    value.and_then(|f| HeaderValue::from_str(&f.fingerprint).ok())
}

/// Convert TLS (JA4) fingerprint to HTTP header value
pub fn tls_header_value(value: Option<&huginn_net_tls::Ja4Payload>) -> Option<HeaderValue> {
    value.and_then(|f| HeaderValue::from_str(&f.full.to_string()).ok())
}

/// Append `client_ip` to the inbound `X-Forwarded-For` chain, or create it if missing.
///
/// Repeated field lines are one list, so every field is kept, in order, and the result
/// is a single comma-joined field with `client_ip` as the rightmost hop. Empty fields are
/// ignored. If any field is not visible ASCII the chain cannot be reproduced faithfully,
/// so it fails closed: the inbound chain is discarded and only `client_ip` is forwarded,
/// rather than forwarding a chain with a hop silently missing.
pub fn append_forwarded_for(headers: &mut hyper::HeaderMap, client_ip: IpAddr) {
    let client_ip = client_ip.to_string();
    let inbound: Option<Vec<&str>> = headers
        .get_all(forwarded::FOR)
        .iter()
        .map(|value| value.to_str().ok().map(str::trim))
        .collect();
    let mut chain: Vec<&str> = inbound
        .unwrap_or_default()
        .into_iter()
        .filter(|field| !field.is_empty())
        .collect();
    chain.push(&client_ip);
    if let Ok(header_value) = HeaderValue::from_str(&chain.join(", ")) {
        headers.insert(forwarded::FOR, header_value);
    }
}

/// Add X-Forwarded-* headers to the request
///
/// This function:
/// 1. Appends client IP to X-Forwarded-For (or creates it if missing)
/// 2. Sets X-Forwarded-Host from the resolved routing host
/// 3. Sets X-Forwarded-Port from the peer's port
/// 4. Sets X-Forwarded-Proto based on is_https flag
pub fn add_forwarded_headers(
    req: &mut Request<Incoming>,
    peer: SocketAddr,
    is_https: bool,
    forwarded_host: &str,
) {
    append_forwarded_for(req.headers_mut(), peer.ip());

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
