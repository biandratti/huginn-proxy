use crate::helpers::create_valid_test_cert;
use huginn_proxy_lib::config::Domain;
use huginn_proxy_lib::telemetry::Metrics;
use huginn_proxy_lib::tls::DynamicCertResolver;

fn domain(host: Option<&str>, cert: &std::path::Path, key: &std::path::Path) -> Domain {
    Domain {
        host: host.map(str::to_string),
        cert_path: Some(cert.display().to_string()),
        key_path: Some(key.display().to_string()),
        headers: None,
        security: None,
        routes: vec![],
    }
}

/// A host-less (catch-all) domain's cert populates the `default` slot, not `exact`.
#[tokio::test]
async fn catch_all_cert_becomes_default() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = create_valid_test_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let domains = vec![domain(None, &cert, &key)];
    let report = resolver.update(&domains, &Metrics::new_noop()).await;

    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
    assert_eq!(report.failed, 0, "valid cert must load");

    let (exact, wildcard, has_default) = resolver.cert_map_summary();
    assert_eq!(exact, 0, "catch-all must not land in the exact map");
    assert_eq!(wildcard, 0, "catch-all must not land in the wildcard map");
    assert!(has_default, "catch-all cert must populate the default slot");
    Ok(())
}

/// Named + wildcard + catch-all are routed to exact / wildcard / default respectively.
#[tokio::test]
async fn certs_routed_by_host_shape() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = create_valid_test_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let domains = vec![
        domain(Some("api.example.com"), &cert, &key),
        domain(Some("*.example.com"), &cert, &key),
        domain(None, &cert, &key),
    ];
    let report = resolver.update(&domains, &Metrics::new_noop()).await;

    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
    assert_eq!(report.failed, 0, "all valid certs must load");

    let (exact, wildcard, has_default) = resolver.cert_map_summary();
    assert_eq!(exact, 1, "exact host → exact map");
    assert_eq!(wildcard, 1, "*.example.com → wildcard map");
    assert!(has_default, "host-less entry → default slot");
    Ok(())
}

/// Without a catch-all, there is no default cert ⇒ unknown/absent SNI is rejected
#[tokio::test]
async fn no_catch_all_means_no_default() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = create_valid_test_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let domains = vec![domain(Some("api.example.com"), &cert, &key)];
    let report = resolver.update(&domains, &Metrics::new_noop()).await;

    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
    assert_eq!(report.failed, 0, "valid cert must load");

    let (_, _, has_default) = resolver.cert_map_summary();
    assert!(!has_default, "no host-less domain ⇒ no default cert ⇒ strict SNI");
    Ok(())
}

/// Lenient (default): unmatched SNI falls back to the default cert; matched SNI and
/// no-SNI both resolve too.
#[tokio::test]
async fn lenient_serves_default_for_unmatched_sni(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = create_valid_test_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let domains = vec![domain(Some("api.example.com"), &cert, &key), domain(None, &cert, &key)];
    let report = resolver.update(&domains, &Metrics::new_noop()).await;
    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
    assert_eq!(report.failed, 0, "all valid certs must load");

    assert!(resolver.resolves_for(Some("api.example.com")), "exact match resolves");
    assert!(
        resolver.resolves_for(Some("unknown.example.org")),
        "unmatched SNI → default cert"
    );
    assert!(resolver.resolves_for(None), "no SNI → default cert");
    Ok(())
}

/// Strict (Traefik `sniStrict` parity): matched SNI resolves, but both unmatched SNI
/// and no-SNI (IP-literal) connections are rejected - the default-cert fallback is off.
#[tokio::test]
async fn strict_rejects_unmatched_and_no_sni(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = create_valid_test_cert()?;
    let resolver = DynamicCertResolver::new(true);

    let domains = vec![domain(Some("api.example.com"), &cert, &key), domain(None, &cert, &key)];
    let report = resolver.update(&domains, &Metrics::new_noop()).await;
    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
    assert_eq!(report.failed, 0, "all valid certs must load");

    assert!(resolver.resolves_for(Some("api.example.com")), "exact match still resolves");
    assert!(
        !resolver.resolves_for(Some("unknown.example.org")),
        "strict: unmatched hostname SNI is rejected"
    );
    assert!(
        !resolver.resolves_for(None),
        "strict: no-SNI (IP-literal) clients are rejected too, even with a default cert present"
    );
    Ok(())
}

#[tokio::test]
async fn wildcard_matches_only_single_label_subdomain(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = create_valid_test_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let domains = vec![domain(Some("*.example.com"), &cert, &key)];
    let report = resolver.update(&domains, &Metrics::new_noop()).await;

    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
    assert_eq!(report.failed, 0, "wildcard cert must load");

    let (_, _, has_default) = resolver.cert_map_summary();
    assert!(!has_default, "no catch-all ⇒ no default fallback to mask misses");

    assert!(
        resolver.resolves_for(Some("sub.example.com")),
        "single-label subdomain matches the wildcard"
    );
    assert!(
        !resolver.resolves_for(Some("example.com")),
        "wildcard does NOT cover the apex/base domain"
    );
    assert!(
        !resolver.resolves_for(Some("a.b.example.com")),
        "wildcard covers exactly one label, not a multi-level subdomain"
    );
    assert!(
        !resolver.resolves_for(Some("notexample.com")),
        "unrelated host does not match the wildcard"
    );
    Ok(())
}

/// Best-effort: one domain's bad cert does not block the others. The valid cert loads,
/// the bad one is reported as failed, and the swap still happens.
#[tokio::test]
async fn bad_cert_does_not_block_other_domains(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = create_valid_test_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let missing = std::path::Path::new("/nonexistent/huginn-test/missing.pem");
    let domains = vec![
        domain(Some("api.example.com"), &cert, &key),
        domain(None, missing, missing), // catch-all with an unreadable cert
    ];
    let report = resolver.update(&domains, &Metrics::new_noop()).await;

    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);

    assert_eq!(report.loaded, 1, "the valid domain cert must load");
    assert_eq!(report.failed, 1, "the unreadable catch-all cert must be reported as failed");
    assert!(report.is_partial(), "a failed cert makes the report partial");

    let (exact, _, has_default) = resolver.cert_map_summary();
    assert_eq!(exact, 1, "valid exact cert went live despite the other failure");
    assert!(!has_default, "first-time failed catch-all has no prior cert to carry over");
    assert!(resolver.resolves_for(Some("api.example.com")), "valid domain still resolves");
    Ok(())
}

#[tokio::test]
async fn mismatched_cert_and_key_is_rejected(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Two independent self-signed pairs; cross cert A with key B.
    let (cert_a, key_a) = create_valid_test_cert()?;
    let (cert_b, key_b) = create_valid_test_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let domains = vec![domain(None, &cert_a, &key_b)];
    let report = resolver.update(&domains, &Metrics::new_noop()).await;

    for path in [&cert_a, &key_a, &cert_b, &key_b] {
        let _ = std::fs::remove_file(path);
    }

    assert_eq!(report.loaded, 0, "a crossed cert/key pair must not load");
    assert_eq!(report.failed, 1, "the mismatched domain is reported as failed");
    let (_, _, has_default) = resolver.cert_map_summary();
    assert!(!has_default, "the mismatched pair must not populate the default slot");
    assert!(!resolver.resolves_for(None), "nothing resolves from a rejected cert/key pair");
    Ok(())
}

/// Best-effort carry-over: a domain that loaded a cert, then fails on a later reload,
/// keeps serving its previously loaded cert instead of going dark.
#[tokio::test]
async fn failed_reload_keeps_previous_cert() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let (cert, key) = create_valid_test_cert()?;
    let resolver = DynamicCertResolver::new(false);

    // First reload: the catch-all loads a valid default cert.
    let good = vec![domain(None, &cert, &key)];
    let first = resolver.update(&good, &Metrics::new_noop()).await;
    assert_eq!(first.failed, 0, "initial load succeeds");
    assert!(resolver.resolves_for(None), "default cert is serving after first load");

    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);

    // Second reload: same domain, but the cert file is now gone (simulates a bad rotation).
    let missing = std::path::Path::new("/nonexistent/huginn-test/missing.pem");
    let bad = vec![domain(None, missing, missing)];
    let second = resolver.update(&bad, &Metrics::new_noop()).await;

    assert_eq!(second.failed, 1, "the failed cert is reported");
    assert_eq!(second.loaded, 0, "nothing new loaded this reload");
    let (_, _, has_default) = resolver.cert_map_summary();
    assert!(has_default, "previously loaded default cert is carried over");
    assert!(
        resolver.resolves_for(None),
        "no-SNI clients keep getting the last-good cert despite the failed reload"
    );
    Ok(())
}
