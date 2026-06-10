use hyper::Request;

/// Extract the effective hostname for domain matching.
///
/// Routing is by the HTTP-layer authority for **all** protocol versions, which
/// mirrors nginx/Traefik/Envoy:
/// 1. URI authority - `:authority` pseudo-header (HTTP/2) or absolute-form request
///    target (HTTP/1.1). For HTTP/2 this is per-request, so a coalesced connection
///    (one TLS session reused across origins under the same cert - RFC 9113 §9.1.1)
///    routes each request to the correct backend. For HTTP/1.1 it honours the host
///    of an absolute-form request target (RFC 7230 §5.3.2).
/// 2. `Host` header - fallback (HTTP/1.1 origin-form, or HTTP/2 without `:authority`).
///
/// TLS SNI is intentionally NOT a routing input. It is used only for certificate
/// selection at the TLS layer ([`crate::tls::DynamicCertResolver`]) and the optional
/// `sni_strict` handshake rejection (exactly like Traefik), whose routers match on
/// the HTTP host while SNI only drives cert / TLS-option selection. Routing uniformly
/// by authority (instead of SNI-first for HTTP/1.1) keeps both protocol versions
/// consistent and follows HTTP host semantics (RFC 7230 §5.4).
///
/// The resolved host returned here is also what `add_forwarded_headers` uses for
/// `X-Forwarded-Host`, so the forwarded host always agrees with the backend the
/// request is routed to.
///
/// IPv6 addresses are returned WITHOUT brackets (`::1` not `[::1]`) to match
/// domain config entries and `http::Uri::host()` canonical form.
///
/// The result is ASCII-lowercased: DNS names and the `Host` header are
/// case-insensitive (RFC 4343 / RFC 7230), and domain config hosts are
/// lowercased at load time, so both sides compare consistently.
pub(crate) fn extract_request_host<B>(req: &Request<B>) -> String {
    extract_request_host_inner(req)
}

pub fn extract_request_host_inner<B>(req: &Request<B>) -> String {
    // URI authority - :authority (HTTP/2) or absolute-form target (HTTP/1.1).
    // strip_host_port normalizes IPv6: http::Uri::host() returns "[::1]" (with
    // brackets); strip_host_port strips them to "::1" to match the domain config.
    if let Some(raw) = req.uri().host() {
        let host = strip_host_port(raw);
        if !host.is_empty() {
            return host.to_ascii_lowercase();
        }
    }

    // Host header fallback (HTTP/1.1 origin-form, or HTTP/2 without :authority).
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
