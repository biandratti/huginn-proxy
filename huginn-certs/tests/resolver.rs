//! SNI resolution + best-effort hot-reload tests for `DynamicCertResolver`.
//!
//! Moved from `huginn-proxy-lib/tests/tls/cert_resolver.rs` when the resolver
//! moved into this crate. They now build [`CertEntry`] directly instead of the
//! proxy's `Domain` type, and read counts from the enriched report via `.len()`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use huginn_certs::{CertEntry, CryptoFileSource, DynamicCertResolver};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Install the aws-lc-rs default crypto provider once (idempotent across tests).
fn ensure_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A self-signed cert/key pair written to a temp dir kept alive by `_dir`.
struct TestCert {
    _dir: tempfile::TempDir,
    cert: PathBuf,
    key: PathBuf,
}

fn make_cert() -> Result<TestCert, Box<dyn std::error::Error + Send + Sync>> {
    ensure_crypto_provider();
    let dir = tempfile::tempdir()?;
    let cert = dir.path().join("test.crt");
    let key = dir.path().join("test.key");

    let rcgen::CertifiedKey { cert: c, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    std::fs::write(&cert, c.pem())?;
    std::fs::write(&key, signing_key.serialize_pem())?;

    Ok(TestCert { _dir: dir, cert, key })
}

fn entry(host: Option<&str>, cert: &Path, key: &Path) -> CertEntry {
    CertEntry {
        host: host.map(str::to_string),
        source: Arc::new(CryptoFileSource::new(cert, key)),
        label: host.unwrap_or("_default_").to_string(),
    }
}

/// A host-less (catch-all) domain's cert populates the `default` slot, not `exact`.
#[tokio::test]
async fn catch_all_cert_becomes_default() -> TestResult {
    let tc = make_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let entries = vec![entry(None, &tc.cert, &tc.key)];
    let report = resolver.update(&entries).await;
    assert!(report.failed.is_empty(), "valid cert must load");

    let (exact, wildcard, has_default) = resolver.cert_map_summary();
    assert_eq!(exact, 0, "catch-all must not land in the exact map");
    assert_eq!(wildcard, 0, "catch-all must not land in the wildcard map");
    assert!(has_default, "catch-all cert must populate the default slot");
    Ok(())
}

/// Named + wildcard + catch-all are routed to exact / wildcard / default respectively.
#[tokio::test]
async fn certs_routed_by_host_shape() -> TestResult {
    let tc = make_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let entries = vec![
        entry(Some("api.example.com"), &tc.cert, &tc.key),
        entry(Some("*.example.com"), &tc.cert, &tc.key),
        entry(None, &tc.cert, &tc.key),
    ];
    let report = resolver.update(&entries).await;
    assert!(report.failed.is_empty(), "all valid certs must load");

    let (exact, wildcard, has_default) = resolver.cert_map_summary();
    assert_eq!(exact, 1, "exact host → exact map");
    assert_eq!(wildcard, 1, "*.example.com → wildcard map");
    assert!(has_default, "host-less entry → default slot");
    Ok(())
}

/// Without a catch-all, there is no default cert ⇒ unknown/absent SNI is rejected.
#[tokio::test]
async fn no_catch_all_means_no_default() -> TestResult {
    let tc = make_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let entries = vec![entry(Some("api.example.com"), &tc.cert, &tc.key)];
    let report = resolver.update(&entries).await;
    assert!(report.failed.is_empty(), "valid cert must load");

    let (_, _, has_default) = resolver.cert_map_summary();
    assert!(!has_default, "no host-less domain ⇒ no default cert ⇒ strict SNI");
    Ok(())
}

/// Lenient (default): unmatched SNI falls back to the default cert; matched SNI and
/// no-SNI both resolve too.
#[tokio::test]
async fn lenient_serves_default_for_unmatched_sni() -> TestResult {
    let tc = make_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let entries = vec![
        entry(Some("api.example.com"), &tc.cert, &tc.key),
        entry(None, &tc.cert, &tc.key),
    ];
    let report = resolver.update(&entries).await;
    assert!(report.failed.is_empty(), "all valid certs must load");

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
async fn strict_rejects_unmatched_and_no_sni() -> TestResult {
    let tc = make_cert()?;
    let resolver = DynamicCertResolver::new(true);

    let entries = vec![
        entry(Some("api.example.com"), &tc.cert, &tc.key),
        entry(None, &tc.cert, &tc.key),
    ];
    let report = resolver.update(&entries).await;
    assert!(report.failed.is_empty(), "all valid certs must load");

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
async fn wildcard_matches_only_single_label_subdomain() -> TestResult {
    let tc = make_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let entries = vec![entry(Some("*.example.com"), &tc.cert, &tc.key)];
    let report = resolver.update(&entries).await;
    assert!(report.failed.is_empty(), "wildcard cert must load");

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
async fn bad_cert_does_not_block_other_domains() -> TestResult {
    let tc = make_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let missing = Path::new("/nonexistent/huginn-test/missing.pem");
    let entries = vec![
        entry(Some("api.example.com"), &tc.cert, &tc.key),
        entry(None, missing, missing), // catch-all with an unreadable cert
    ];
    let report = resolver.update(&entries).await;

    assert_eq!(report.loaded.len(), 1, "the valid domain cert must load");
    assert_eq!(
        report.failed.len(),
        1,
        "the unreadable catch-all cert must be reported as failed"
    );
    assert!(report.is_partial(), "a failed cert makes the report partial");

    let (exact, _, has_default) = resolver.cert_map_summary();
    assert_eq!(exact, 1, "valid exact cert went live despite the other failure");
    assert!(!has_default, "first-time failed catch-all has no prior cert to carry over");
    assert!(resolver.resolves_for(Some("api.example.com")), "valid domain still resolves");
    Ok(())
}

#[tokio::test]
async fn mismatched_cert_and_key_is_rejected() -> TestResult {
    // Two independent self-signed pairs; cross cert A with key B.
    let tc_a = make_cert()?;
    let tc_b = make_cert()?;
    let resolver = DynamicCertResolver::new(false);

    let entries = vec![entry(None, &tc_a.cert, &tc_b.key)];
    let report = resolver.update(&entries).await;

    assert!(report.loaded.is_empty(), "a crossed cert/key pair must not load");
    assert_eq!(report.failed.len(), 1, "the mismatched domain is reported as failed");
    let (_, _, has_default) = resolver.cert_map_summary();
    assert!(!has_default, "the mismatched pair must not populate the default slot");
    assert!(!resolver.resolves_for(None), "nothing resolves from a rejected cert/key pair");
    Ok(())
}

/// Best-effort carry-over: a domain that loaded a cert, then fails on a later reload,
/// keeps serving its previously loaded cert instead of going dark.
#[tokio::test]
async fn failed_reload_keeps_previous_cert() -> TestResult {
    let tc = make_cert()?;
    let resolver = DynamicCertResolver::new(false);

    // First reload: the catch-all loads a valid default cert.
    let good = vec![entry(None, &tc.cert, &tc.key)];
    let first = resolver.update(&good).await;
    assert!(first.failed.is_empty(), "initial load succeeds");
    assert!(resolver.resolves_for(None), "default cert is serving after first load");

    // Second reload: same domain, but the cert file is now gone (simulates a bad rotation).
    let missing = Path::new("/nonexistent/huginn-test/missing.pem");
    let bad = vec![entry(None, missing, missing)];
    let second = resolver.update(&bad).await;

    assert_eq!(second.failed.len(), 1, "the failed cert is reported");
    assert!(second.loaded.is_empty(), "nothing new loaded this reload");
    let (_, _, has_default) = resolver.cert_map_summary();
    assert!(has_default, "previously loaded default cert is carried over");
    assert!(
        resolver.resolves_for(None),
        "no-SNI clients keep getting the last-good cert despite the failed reload"
    );
    Ok(())
}
