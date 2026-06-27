use std::sync::Arc;

use huginn_proxy_lib::tls::{CompositeResolver, DynamicCertResolver};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

/// Stand-in ACME resolver: presence in the map is all the routing tests check.
#[derive(Debug)]
struct DummyResolver;

impl ResolvesServerCert for DummyResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        None
    }
}

fn acme_pair(host: &str) -> (String, Arc<dyn ResolvesServerCert>) {
    (host.to_string(), Arc::new(DummyResolver) as Arc<dyn ResolvesServerCert>)
}

#[test]
fn routes_known_acme_host_to_acme_resolver() {
    let composite = CompositeResolver::new(
        Arc::new(DynamicCertResolver::new(false)),
        vec![acme_pair("api.example.com")],
    );
    assert!(composite.routes_to_acme(Some("api.example.com")));
}

#[test]
fn falls_through_for_unknown_host_and_no_sni() {
    let composite = CompositeResolver::new(
        Arc::new(DynamicCertResolver::new(false)),
        vec![acme_pair("api.example.com")],
    );
    // Unknown SNI → static resolver.
    assert!(!composite.routes_to_acme(Some("other.example.com")));
    // No SNI (IP-literal client) → static resolver.
    assert!(!composite.routes_to_acme(None));
}

#[test]
fn sni_lookup_is_case_insensitive() {
    let composite = CompositeResolver::new(
        Arc::new(DynamicCertResolver::new(false)),
        // Host registered in mixed case is lowercased on insert.
        vec![acme_pair("API.Example.COM")],
    );
    assert!(composite.routes_to_acme(Some("api.example.com")));
}

#[test]
fn has_serviceable_cert_counts_acme_only_deploy() {
    // No static certs at all, one ACME host → still serviceable (no spurious warning).
    let composite = CompositeResolver::new(
        Arc::new(DynamicCertResolver::new(false)),
        vec![acme_pair("api.example.com")],
    );
    assert!(composite.has_serviceable_cert());
}

#[test]
fn has_serviceable_cert_false_when_empty() {
    let composite = CompositeResolver::new(Arc::new(DynamicCertResolver::new(false)), Vec::new());
    assert!(!composite.has_serviceable_cert());
}
