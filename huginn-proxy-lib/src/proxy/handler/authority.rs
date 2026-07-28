//! Whether a request's `Host` is allowed to travel over the connection that carried it.
//!
//! A single TLS connection can be reused for requests naming different hosts
//! (HTTP/2 coalescing, RFC 9113 §9.1.1), so the request authority is not necessarily
//! the SNI that selected the connection's certificate. The rules that decide when
//! that divergence is acceptable live here, together, because they constrain each
//! other: certificate coverage alone is not sufficient once a domain requires client
//! authentication.
//!
//! Domain matching itself ([`pick_domain`]) stays in [`crate::proxy::router`].

use crate::config::Domain;
use crate::proxy::router::pick_domain;

/// The certificate a domain is effectively served with: its own `cert_path`, or the
/// default certificate (the catch-all/host-less domain's `cert_path`) when it declares
/// none. Mirrors `ServerCryptoMap`'s exact → wildcard → default resolution.
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
