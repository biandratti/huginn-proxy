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
        routes: vec![],
    }
}

/// A host-less (catch-all) domain's cert populates the `default` slot, not `exact`.
#[tokio::test]
async fn catch_all_cert_becomes_default() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = create_valid_test_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let domains = vec![domain(None, &cert, &key)];
    let result = resolver.update(&domains, &Metrics::new_noop()).await;

    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
    result?;

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
    let result = resolver.update(&domains, &Metrics::new_noop()).await;

    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
    result?;

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
    let result = resolver.update(&domains, &Metrics::new_noop()).await;

    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
    result?;

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
    let result = resolver.update(&domains, &Metrics::new_noop()).await;
    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
    result?;

    assert!(resolver.resolves_for(Some("api.example.com")), "exact match resolves");
    assert!(
        resolver.resolves_for(Some("unknown.example.org")),
        "unmatched SNI → default cert"
    );
    assert!(resolver.resolves_for(None), "no SNI → default cert");
    Ok(())
}

/// Strict: unmatched SNI is rejected, but matched SNI and no-SNI (IP clients) still resolve.
#[tokio::test]
async fn strict_rejects_unmatched_sni_but_keeps_no_sni(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = create_valid_test_cert()?;
    let resolver = DynamicCertResolver::new(true);

    let domains = vec![domain(Some("api.example.com"), &cert, &key), domain(None, &cert, &key)];
    let result = resolver.update(&domains, &Metrics::new_noop()).await;
    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
    result?;

    assert!(resolver.resolves_for(Some("api.example.com")), "exact match still resolves");
    assert!(
        !resolver.resolves_for(Some("unknown.example.org")),
        "strict: unmatched hostname SNI is rejected"
    );
    assert!(
        resolver.resolves_for(None),
        "strict still serves the default cert to no-SNI (IP) clients"
    );
    Ok(())
}
