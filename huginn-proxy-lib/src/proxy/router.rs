use crate::config::{Domain, Route};

#[derive(Debug, Clone)]
pub struct RouteMatch<'a> {
    pub backend: &'a str,
    pub backend_candidates: Vec<&'a str>,
    pub fingerprinting: Option<bool>,
    pub matched_prefix: &'a str,
    pub replace_path: Option<&'a str>,
    pub rate_limit: Option<&'a crate::config::RateLimitConfig>,
    pub ip_filter: Option<&'a crate::config::IpFilterConfig>,
    pub security_headers: Option<&'a crate::config::SecurityHeaders>,
    pub headers: Option<&'a crate::config::HeaderManipulation>,
    pub force_new_connection: bool,
}

/// Returns true when `prefix` is a valid match for `path`.
///
/// A prefix matches if `path` starts with it AND the character immediately after is `/`
/// (sub-path) or the strings are equal (exact match). The root prefix `/` always matches.
/// This prevents `/api` from inadvertently matching `/api2`.
pub fn prefix_matches(path: &str, prefix: &str) -> bool {
    if !path.starts_with(prefix) {
        return false;
    }
    prefix == "/" || path.len() == prefix.len() || path.as_bytes()[prefix.len()] == b'/'
}

/// Returns the first route with the longest matching prefix.
///
/// Relies on routes being pre-sorted by prefix length descending (done in `Config::into_parts`),
/// so the first match is by definition the most specific one.
fn longest_match<'a>(path: &str, routes: &'a [Route]) -> Option<&'a Route> {
    routes.iter().find(|r| prefix_matches(path, &r.prefix))
}

pub fn pick_route<'a>(path: &str, routes: &'a [Route]) -> Option<&'a str> {
    longest_match(path, routes).map(|r| r.backend.as_str())
}

/// Finds the domain entry that matches `host`.
///
/// Matching order (most specific first):
/// 1. Exact: `"api.example.com"` == host
/// 2. Wildcard: `"*.example.com"` where host is `"sub.example.com"` (one level only;
///    skipped for dotless hosts like `localhost`, which fall through to the catch-all)
/// 3. Catch-all: the first domain with no `host`
/// 4. `None`, no exact/wildcard match and no catch-all configured.
///    (The request handler maps this to HTTP 421 Misdirected Request.)
pub fn pick_domain<'a>(domains: &'a [Domain], host: &str) -> Option<&'a Domain> {
    // 1. Exact match
    if let Some(d) = domains.iter().find(|d| d.host.as_deref() == Some(host)) {
        return Some(d);
    }
    // 2. Wildcard: strip leftmost label and compare base domain.
    //    Skipped (not early-returned) when `host` has no dot, so labels like
    //    "localhost" still fall through to the catch-all below.
    if let Some(dot) = host.find('.') {
        let base = &host[dot.saturating_add(1)..];
        if let Some(d) = domains.iter().find(|d| {
            d.host
                .as_deref()
                .is_some_and(|h| h.starts_with("*.") && h.get(2..) == Some(base))
        }) {
            return Some(d);
        }
    }
    // 3. Catch-all: first host-less domain.
    domains.iter().find(|d| d.host.is_none())
}

/// The certificate a domain is effectively served with: its own `cert_path`, or the
/// default certificate (the catch-all/host-less domain's `cert_path`) when it declares
/// none. Mirrors `DynamicCertResolver`'s exact → wildcard → default resolution.
fn effective_cert_path<'a>(domain: &'a Domain, default_cert: Option<&'a str>) -> Option<&'a str> {
    domain.cert_path.as_deref().or(default_cert)
}

/// Whether a request `host` is authoritative for a TLS connection whose SNI was `sni`,
/// i.e. the certificate the connection's SNI selected also covers `host`.
///
/// Backs the always-on `421 Misdirected Request` enforcement (RFC 9110 §15.5.20 /
/// RFC 7540 §9.1.2), the same protection nginx and Apache `mod_http2` apply by default
/// to HTTP/2 connection reuse. Because huginn uses a single global TLS configuration, the
/// only thing that varies per host is the certificate, so "authoritative" reduces to
/// "served by the same certificate".
///
/// It compares **certificate coverage**, not literal `authority == SNI`, so legitimate
/// coalescing keeps working: a shared wildcard entry (`api`/`docs.example.com` under
/// `*.example.com`) or distinct `[[domains]]` pointing at the same SAN cert file both
/// resolve to the same certificate and are allowed. Only a host whose certificate differs
/// from the connection's is rejected (caller maps to HTTP 421).
///
/// `host` is expected already lowercased (as returned by `extract_request_host`); `sni`
/// is lowercased here.
pub fn authority_matches_sni(domains: &[Domain], sni: &str, host: &str) -> bool {
    let sni = sni.to_ascii_lowercase();
    match (pick_domain(domains, &sni), pick_domain(domains, host)) {
        (Some(sni_domain), Some(host_domain)) => {
            // Same domain entry (covers single-entry wildcard coalescing).
            if std::ptr::eq(sni_domain, host_domain) {
                return true;
            }
            // Otherwise: same effective certificate ⇒ the connection's cert covers `host`.
            let default_cert = domains
                .iter()
                .find(|d| d.host.is_none())
                .and_then(|d| d.cert_path.as_deref());
            let sni_cert = effective_cert_path(sni_domain, default_cert);
            let host_cert = effective_cert_path(host_domain, default_cert);
            sni_cert.is_some() && sni_cert == host_cert
        }
        (None, None) => true,
        _ => false,
    }
}

pub fn pick_route_with_fingerprinting<'a>(
    path: &str,
    routes: &'a [Route],
) -> Option<RouteMatch<'a>> {
    let pos = routes
        .iter()
        .position(|r| prefix_matches(path, &r.prefix))?;
    let first = &routes[pos];

    let backend_candidates = routes[pos..]
        .iter()
        .take_while(|r| r.prefix.len() == first.prefix.len())
        .filter(|r| r.prefix == first.prefix)
        .map(|r| r.backend.as_str())
        .collect::<Vec<_>>();

    let security = first.security.as_ref();
    Some(RouteMatch {
        backend: first.backend.as_str(),
        backend_candidates,
        fingerprinting: first.fingerprinting,
        matched_prefix: first.prefix.as_str(),
        replace_path: first.replace_path.as_deref(),
        rate_limit: security.and_then(|s| s.rate_limit.as_ref()),
        ip_filter: security.and_then(|s| s.ip_filter.as_ref()),
        security_headers: security.and_then(|s| s.headers.as_ref()),
        headers: first.headers.as_ref(),
        force_new_connection: first.force_new_connection,
    })
}
