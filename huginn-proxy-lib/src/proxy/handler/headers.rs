use huginn_net_http::AkamaiFingerprint;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::Request;
use std::net::SocketAddr;

use crate::fingerprinting::headers::forwarded;

/// Convert Akamai fingerprint to HTTP header value
pub fn akamai_header_value(value: &Option<AkamaiFingerprint>) -> Option<HeaderValue> {
    value
        .as_ref()
        .and_then(|f| HeaderValue::from_str(&f.fingerprint).ok())
}

/// Convert TLS (JA4) fingerprint to HTTP header value
pub fn tls_header_value(value: &Option<huginn_net_tls::Ja4Payload>) -> Option<HeaderValue> {
    value
        .as_ref()
        .and_then(|f| HeaderValue::from_str(&f.full.to_string()).ok())
}

/// Add X-Forwarded-* headers to the request
///
/// This function:
/// 1. Appends client IP to X-Forwarded-For (or creates it if missing)
/// 2. Sets X-Forwarded-Host from the request's Host header
/// 3. Sets X-Forwarded-Port from the peer's port
/// 4. Sets X-Forwarded-Proto based on is_https flag
///
/// This matches the behavior of Go's httputil.ProxyRequest.SetXForwarded()
pub fn add_forwarded_headers(req: &mut Request<Incoming>, peer: SocketAddr, is_https: bool) {
    // X-Forwarded-For: Append client IP to existing header, or create new one
    let client_ip = peer.ip().to_string();
    if let Some(existing_for) = req.headers().get(forwarded::FOR) {
        // Append to existing header (comma-separated)
        if let Ok(existing_str) = existing_for.to_str() {
            let new_value = format!("{existing_str}, {client_ip}");
            if let Ok(header_value) = HeaderValue::from_str(&new_value) {
                req.headers_mut().insert(forwarded::FOR, header_value);
            }
        }
    } else {
        // Create new header
        if let Ok(header_value) = HeaderValue::from_str(&client_ip) {
            req.headers_mut().insert(forwarded::FOR, header_value);
        }
    }

    // X-Forwarded-Host: Use the Host header from the original request
    if let Some(host) = req.headers().get("host") {
        if let Ok(host_str) = host.to_str() {
            if let Ok(header_value) = HeaderValue::from_str(host_str) {
                req.headers_mut().insert(forwarded::HOST, header_value);
            }
        }
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
