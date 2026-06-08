use hyper::Request;

/// Extract the effective hostname for domain matching.
///
/// Priority:
/// 1. TLS SNI - authoritative; set by the TLS layer before any HTTP is read.
/// 2. URI authority - `:authority` pseudo-header (HTTP/2) or absolute-form URI (HTTP/1.1).
///    Cannot be forged via application-level headers.
/// 3. `Host` header - fallback for HTTP/1.1 origin-form requests.
///
/// IPv6 addresses are returned WITHOUT brackets (`::1` not `[::1]`) to match
/// domain config entries and `http::Uri::host()` canonical form.
///
/// The result is ASCII-lowercased: DNS names and the `Host` header are
/// case-insensitive (RFC 4343 / RFC 7230), and domain config hosts are
/// lowercased at load time, so both sides compare consistently.
pub(crate) fn extract_request_host<B>(
    req: &Request<B>,
    ja4: Option<&crate::fingerprinting::Ja4Fingerprints>,
    is_https: bool,
) -> String {
    let sni = ja4.and_then(|fp| fp.sni.as_deref());
    extract_request_host_inner(req, sni, is_https)
}

pub fn extract_request_host_inner<B>(
    req: &Request<B>,
    sni: Option<&str>,
    is_https: bool,
) -> String {
    // 1. TLS SNI
    if is_https {
        if let Some(s) = sni {
            return s.to_ascii_lowercase();
        }
    }
    // 2. URI authority - present for HTTP/2 and absolute-form HTTP/1.1.
    //    strip_host_port normalizes IPv6: http::Uri::host() returns "[::1]" (with
    //    brackets); strip_host_port strips them to "::1" to match the domain config.
    if let Some(raw) = req.uri().host() {
        let host = strip_host_port(raw);
        if !host.is_empty() {
            return host.to_ascii_lowercase();
        }
    }
    // 3. Host header fallback (HTTP/1.1 origin-form, or HTTP/2 without :authority)
    req.headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(strip_host_port)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default()
}

/// Strip port from a `Host` header value and normalise IPv6 addresses.
///
/// Returns the bare hostname without port and without IPv6 brackets:
/// - `"[::1]:8080"` → `"::1"`
/// - `"[::1]"` → `"::1"`
/// - `"example.com:8080"` → `"example.com"`
/// - `"127.0.0.1:7000"` → `"127.0.0.1"`
#[doc(hidden)]
pub fn strip_host_port(host: &str) -> &str {
    if host.starts_with('[') {
        // IPv6: strip leading '[' and everything from ']' onward.
        host.find(']').map_or(host, |end| &host[1..end])
    } else {
        host.split_once(':').map_or(host, |(h, _)| h)
    }
}
