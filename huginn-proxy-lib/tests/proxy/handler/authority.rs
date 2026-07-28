use huginn_proxy_lib::config::Domain;
use huginn_proxy_lib::proxy::handler::authority_matches_sni;

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
