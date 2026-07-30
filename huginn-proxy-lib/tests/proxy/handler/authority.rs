use huginn_proxy_lib::config::Domain;
use huginn_proxy_lib::proxy::handler::{
    authority_matches_sni, mutual_tls_session_matches, strip_trailing_dot,
};

fn domain(host: &str) -> Domain {
    Domain {
        host: Some(host.to_string()),
        cert_path: None,
        key_path: None,
        client_ca_path: None,
        headers: None,
        security: None,
        fingerprinting: None,
        routes: vec![],
    }
}

fn domain_with_cert(host: &str, cert_path: &str) -> Domain {
    Domain {
        host: Some(host.to_string()),
        cert_path: Some(cert_path.to_string()),
        key_path: Some(format!("{cert_path}.key")),
        client_ca_path: None,
        headers: None,
        security: None,
        fingerprinting: None,
        routes: vec![],
    }
}

/// A host-less (catch-all) domain matches any host not matched exactly/by wildcard.
fn catch_all() -> Domain {
    Domain {
        host: None,
        cert_path: None,
        key_path: None,
        client_ca_path: None,
        headers: None,
        security: None,
        fingerprinting: None,
        routes: vec![],
    }
}

#[test]
fn authority_matches_sni_same_host() {
    let domains = vec![domain("api.example.com")];
    assert!(authority_matches_sni(&domains, "api.example.com", "api.example.com"));
}

#[test]
fn authority_matches_sni_is_case_insensitive_on_sni() {
    let domains = vec![domain("api.example.com")];
    // `host` arrives already lowercased; the SNI is lowercased internally.
    assert!(authority_matches_sni(&domains, "API.Example.COM", "api.example.com"));
}

#[test]
fn authority_matches_sni_allows_wildcard_coalescing() {
    // The coalescing case we must NOT break: two hosts served by one *.example.com cert.
    let domains = vec![domain("*.example.com")];
    assert!(authority_matches_sni(&domains, "api.example.com", "docs.example.com"));
}

#[test]
fn authority_matches_sni_rejects_cross_certificate() {
    // SNI selected the exact api cert; a request for a host on a *different* cert is rejected.
    let domains = vec![domain("api.example.com"), domain("*.example.com")];
    // SNI -> exact api.example.com; authority -> *.example.com (different domain/cert).
    assert!(!authority_matches_sni(&domains, "api.example.com", "docs.example.com"));
}

#[test]
fn authority_matches_sni_rejects_unrelated_host() {
    let domains = vec![domain("api.example.com")];
    // authority resolves to no domain at all -> not authoritative.
    assert!(!authority_matches_sni(&domains, "api.example.com", "evil.com"));
}

#[test]
fn authority_matches_sni_both_catch_all_match() {
    let domains = vec![catch_all()];
    assert!(authority_matches_sni(&domains, "anything.com", "other.com"));
}

#[test]
fn authority_matches_sni_specific_sni_vs_catch_all_host() {
    let domains = vec![domain("api.example.com"), catch_all()];
    // SNI -> exact domain, authority -> catch-all: different cert, reject.
    assert!(!authority_matches_sni(&domains, "api.example.com", "other.com"));
}

#[test]
fn authority_matches_sni_same_cert_file_coalesces() {
    // Two distinct domain entries pointing at the same SAN certificate file: the
    // connection's cert covers both, so coalescing must be allowed (no false 421).
    let domains = vec![
        domain_with_cert("api.example.com", "/certs/san.pem"),
        domain_with_cert("docs.example.com", "/certs/san.pem"),
    ];
    assert!(authority_matches_sni(&domains, "api.example.com", "docs.example.com"));
}

#[test]
fn authority_matches_sni_different_cert_files_rejected() {
    let domains = vec![
        domain_with_cert("api.example.com", "/certs/api.pem"),
        domain_with_cert("other.com", "/certs/other.pem"),
    ];
    // SNI selected api's cert; a request for other.com (a different cert) is misdirected.
    assert!(!authority_matches_sni(&domains, "api.example.com", "other.com"));
}

#[test]
fn authority_matches_sni_certless_host_uses_default_cert() {
    // A certless named domain is served by the default (catch-all) cert. A request for it
    // over a connection that also presented the default cert coalesces.
    let catch_all_with_cert = Domain {
        cert_path: Some("/certs/default.pem".to_string()),
        key_path: Some("/certs/default.key".to_string()),
        ..catch_all()
    };
    let domains = vec![domain("api.example.com"), catch_all_with_cert];
    // SNI=api.example.com -> certless -> default cert; authority=other -> catch-all -> default cert.
    assert!(authority_matches_sni(&domains, "api.example.com", "other.com"));
}

fn mtls_domain(host: &str, cert_path: &str) -> Domain {
    Domain {
        client_ca_path: Some("/certs/client-ca.pem".to_string()),
        ..domain_with_cert(host, cert_path)
    }
}

/// `public` (no client auth) and `admin` (client auth) sharing one SAN certificate.
fn shared_cert_domains() -> Vec<Domain> {
    vec![
        domain_with_cert("public.example.com", "/certs/san.pem"),
        mtls_domain("admin.example.com", "/certs/san.pem"),
    ]
}

fn resolve<'a>(domains: &'a [Domain], host: &str) -> &'a Domain {
    huginn_proxy_lib::proxy::router::pick_domain(domains, host)
        .unwrap_or_else(|| panic!("{host} must resolve to a domain"))
}

/// The bypass: a session opened with the non-mTLS domain's SNI must not reach the
/// mTLS domain just because both are served by the same certificate.
#[test]
fn mtls_rejects_foreign_sni_on_shared_certificate() {
    let domains = shared_cert_domains();
    let admin = resolve(&domains, "admin.example.com");

    // Same certificate, so the coalescing check alone would let this through.
    assert!(authority_matches_sni(&domains, "public.example.com", "admin.example.com"));
    assert!(!mutual_tls_session_matches(&domains, admin, true, Some("public.example.com")));
}

/// A TLS session without SNI (IP-literal client under `sni_strict = false`) never
/// passed the domain's client verifier.
#[test]
fn mtls_rejects_missing_sni() {
    let domains = shared_cert_domains();
    let admin = resolve(&domains, "admin.example.com");
    assert!(!mutual_tls_session_matches(&domains, admin, true, None));
}

/// Plaintext cannot have performed client authentication at all.
#[test]
fn mtls_rejects_plaintext() {
    let domains = shared_cert_domains();
    let admin = resolve(&domains, "admin.example.com");
    assert!(!mutual_tls_session_matches(&domains, admin, false, Some("admin.example.com")));
}

#[test]
fn mtls_allows_its_own_sni() {
    let domains = shared_cert_domains();
    let admin = resolve(&domains, "admin.example.com");
    assert!(mutual_tls_session_matches(&domains, admin, true, Some("admin.example.com")));
    // The SNI is lowercased before matching, like in `authority_matches_sni`.
    assert!(mutual_tls_session_matches(&domains, admin, true, Some("Admin.Example.COM")));
}

/// Coalescing under a single wildcard mTLS entry stays allowed: both hosts were served
/// by that entry's own `ServerConfig`, so the client did authenticate against its CA.
#[test]
fn mtls_allows_coalescing_within_one_wildcard_entry() {
    let domains = vec![mtls_domain("*.example.com", "/certs/wildcard.pem")];
    let docs = resolve(&domains, "docs.example.com");
    assert!(mutual_tls_session_matches(&domains, docs, true, Some("api.example.com")));
}

/// Domains without client auth are untouched: the shared-certificate relaxation still
/// applies to them, so no new 421s for legitimate coalescing.
#[test]
fn non_mtls_domains_are_unaffected() {
    let domains = shared_cert_domains();
    let public = resolve(&domains, "public.example.com");
    assert!(mutual_tls_session_matches(&domains, public, true, Some("admin.example.com")));
    assert!(mutual_tls_session_matches(&domains, public, true, None));
    assert!(mutual_tls_session_matches(&domains, public, false, None));
}

/// The TLS transport strips a client's trailing-dot SNI (`admin.example.com.`) before
/// it ever reaches this module (see `proxy/transport/tls.rs`); this documents that
/// contract at the unit level: once normalized, an FQDN-form SNI resolves to the same
/// domain as a dot-less `Host`, so an FQDN client no longer gets the spurious 421 that
/// the config/HTTP/TLS host-comparison mismatch used to produce.
#[test]
fn authority_matches_sni_after_trailing_dot_normalization() {
    let domains = vec![domain("admin.example.com")];
    let normalized_sni = strip_trailing_dot("admin.example.com.");
    assert!(authority_matches_sni(&domains, normalized_sni, "admin.example.com"));
}

/// The mTLS bypass guard still fails closed for an FQDN-form foreign SNI: normalizing
/// the trailing dot must not create a new way to reach the mTLS domain from a session
/// opened with a different domain's SNI.
#[test]
fn mtls_rejects_foreign_sni_in_fqdn_form() {
    let domains = shared_cert_domains();
    let admin = resolve(&domains, "admin.example.com");
    let foreign_sni = strip_trailing_dot("public.example.com.");
    assert!(!mutual_tls_session_matches(&domains, admin, true, Some(foreign_sni)));
}
