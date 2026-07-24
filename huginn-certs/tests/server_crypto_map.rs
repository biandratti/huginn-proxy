//! Per-SNI `ServerConfig` build + selection tests for [`build_server_crypto`].
//!
//! Cover huginn's resolution model preserved on the per-SNI map (exact → wildcard
//! → catch-all + `sni_strict`), best-effort carry-forward, and the rpxy resumption
//! policy: non-mTLS configs issue stateless tickets from one shared ticketer while
//! mTLS configs never resume so the client cert is verified on every connection.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use huginn_certs::{
    build_server_crypto, CertEntry, CryptoFileSource, ServerCryptoMap, TlsBuildOptions,
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Install the aws-lc-rs default crypto provider once (idempotent across tests).
fn ensure_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A self-signed server pair plus a stand-in client-CA bundle, under a temp dir
/// kept alive by `_dir`.
struct Fixture {
    _dir: tempfile::TempDir,
    cert: PathBuf,
    key: PathBuf,
    client_ca: PathBuf,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error + Send + Sync>> {
    ensure_crypto_provider();
    let dir = tempfile::tempdir()?;
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");
    let client_ca = dir.path().join("client-ca.crt");

    let server = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    std::fs::write(&cert, server.cert.pem())?;
    std::fs::write(&key, server.signing_key.serialize_pem())?;

    let ca = rcgen::generate_simple_self_signed(vec!["client-ca".to_string()])?;
    std::fs::write(&client_ca, ca.cert.pem())?;

    Ok(Fixture { _dir: dir, cert, key, client_ca })
}

fn options(resumption_enabled: bool, sni_strict: bool) -> TlsBuildOptions {
    TlsBuildOptions { resumption_enabled, sni_strict, ..Default::default() }
}

fn entry(host: Option<&str>, cert: &Path, key: &Path) -> CertEntry {
    CertEntry {
        host: host.map(str::to_string),
        source: Arc::new(CryptoFileSource::new(cert, key)),
        label: host.unwrap_or("_default_").to_string(),
    }
}

fn mtls_entry(host: Option<&str>, cert: &Path, key: &Path, ca: &Path) -> CertEntry {
    CertEntry {
        host: host.map(str::to_string),
        source: Arc::new(CryptoFileSource::new(cert, key).with_client_ca(ca)),
        label: host.unwrap_or("_default_").to_string(),
    }
}

async fn build(
    entries: &[CertEntry],
    opts: &TlsBuildOptions,
    previous: Option<&ServerCryptoMap>,
) -> Result<
    (ServerCryptoMap, huginn_certs::CertReloadReport),
    Box<dyn std::error::Error + Send + Sync>,
> {
    Ok(build_server_crypto(entries, opts, previous).await?)
}

/// Named + wildcard + catch-all land in exact / wildcard / default respectively.
#[tokio::test]
async fn configs_routed_by_host_shape() -> TestResult {
    let fx = fixture()?;
    let entries = vec![
        entry(Some("api.example.com"), &fx.cert, &fx.key),
        entry(Some("*.example.com"), &fx.cert, &fx.key),
        entry(None, &fx.cert, &fx.key),
    ];
    let (map, report) = build(&entries, &options(true, false), None).await?;

    assert!(report.failed.is_empty(), "all valid certs must load");
    assert_eq!(map.config_summary(), (1, 1, true), "one exact, one wildcard, a default");
    Ok(())
}

/// Lenient: exact match, unmatched SNI, and no-SNI all resolve (to default).
#[tokio::test]
async fn lenient_serves_default_for_unmatched_sni() -> TestResult {
    let fx = fixture()?;
    let entries = vec![
        entry(Some("api.example.com"), &fx.cert, &fx.key),
        entry(None, &fx.cert, &fx.key),
    ];
    let (map, _) = build(&entries, &options(true, false), None).await?;

    assert!(map.resolves_for(Some("api.example.com")), "exact match resolves");
    assert!(map.resolves_for(Some("unknown.example.org")), "unmatched SNI → default");
    assert!(map.resolves_for(None), "no SNI → default");
    Ok(())
}

/// Strict: exact match resolves; unmatched SNI and no-SNI are rejected (no fallback).
#[tokio::test]
async fn strict_rejects_unmatched_and_no_sni() -> TestResult {
    let fx = fixture()?;
    let entries = vec![
        entry(Some("api.example.com"), &fx.cert, &fx.key),
        entry(None, &fx.cert, &fx.key),
    ];
    let (map, _) = build(&entries, &options(true, true), None).await?;

    assert!(map.resolves_for(Some("api.example.com")), "exact match still resolves");
    assert!(!map.resolves_for(Some("unknown.example.org")), "strict: unmatched SNI rejected");
    assert!(!map.resolves_for(None), "strict: no-SNI rejected even with a default present");
    Ok(())
}

/// Wildcard covers exactly one label: not the apex, not multi-level, not unrelated hosts.
#[tokio::test]
async fn wildcard_matches_only_single_label_subdomain() -> TestResult {
    let fx = fixture()?;
    let entries = vec![entry(Some("*.example.com"), &fx.cert, &fx.key)];
    let (map, _) = build(&entries, &options(true, false), None).await?;

    assert!(map.resolves_for(Some("sub.example.com")), "single-label subdomain matches");
    assert!(!map.resolves_for(Some("example.com")), "wildcard excludes the apex");
    assert!(!map.resolves_for(Some("a.b.example.com")), "wildcard excludes multi-level");
    assert!(!map.resolves_for(Some("notexample.com")), "unrelated host does not match");
    Ok(())
}

/// No catch-all ⇒ no default; a strict/no-match still yields the reject sentinel config.
#[tokio::test]
async fn reject_config_available_without_default() -> TestResult {
    let fx = fixture()?;
    let entries = vec![entry(Some("api.example.com"), &fx.cert, &fx.key)];
    let (map, _) = build(&entries, &options(true, false), None).await?;

    assert_eq!(map.config_summary(), (1, 0, false), "no host-less domain ⇒ no default");
    assert!(map.has_serviceable_config(), "one exact config is serviceable");
    // The sentinel is always available for the accept path to abort a no-match handshake.
    let _reject = map.reject_config();
    Ok(())
}

/// Best-effort: one domain's unreadable cert is reported failed; the others still load.
#[tokio::test]
async fn bad_cert_does_not_block_other_domains() -> TestResult {
    let fx = fixture()?;
    let missing = Path::new("/nonexistent/huginn-test/missing.pem");
    let entries =
        vec![entry(Some("api.example.com"), &fx.cert, &fx.key), entry(None, missing, missing)];
    let (map, report) = build(&entries, &options(true, false), None).await?;

    assert_eq!(report.loaded.len(), 1, "the valid domain cert loads");
    assert_eq!(report.failed.len(), 1, "the unreadable catch-all is reported failed");
    assert!(report.is_partial(), "a failed cert makes the report partial");
    assert_eq!(map.config_summary(), (1, 0, false), "valid exact config went live");
    Ok(())
}

/// Carry-forward: a domain that loaded, then fails on rebuild, keeps its old config.
#[tokio::test]
async fn failed_rebuild_keeps_previous_config() -> TestResult {
    let fx = fixture()?;
    let good = vec![entry(None, &fx.cert, &fx.key)];
    let (first, first_report) = build(&good, &options(true, false), None).await?;
    assert!(first_report.failed.is_empty(), "initial build succeeds");
    assert!(first.resolves_for(None), "default config serving after first build");

    let missing = Path::new("/nonexistent/huginn-test/missing.pem");
    let bad = vec![entry(None, missing, missing)];
    let (second, second_report) = build(&bad, &options(true, false), Some(&first)).await?;

    assert_eq!(second_report.failed.len(), 1, "the failed cert is reported");
    assert!(second_report.loaded.is_empty(), "nothing new loaded this rebuild");
    assert!(second.resolves_for(None), "no-SNI clients keep the last-good config");
    Ok(())
}

/// Non-mTLS + resumption on: stateless tickets, no server-side session cache.
#[tokio::test]
async fn non_mtls_uses_stateless_tickets_without_cache() -> TestResult {
    let fx = fixture()?;
    let entries = vec![entry(Some("example.com"), &fx.cert, &fx.key)];
    let (map, _) = build(&entries, &options(true, false), None).await?;

    let cfg = map
        .select(Some("example.com"))
        .ok_or("example.com must resolve")?;
    assert!(cfg.ticketer.enabled(), "non-mTLS config must issue stateless tickets");
    assert!(
        !cfg.session_storage.can_cache(),
        "non-mTLS config keeps no server-side session state"
    );
    Ok(())
}

/// Resumption disabled: no ticketer anywhere.
#[tokio::test]
async fn resumption_disabled_means_no_ticketer() -> TestResult {
    let fx = fixture()?;
    let entries = vec![entry(Some("example.com"), &fx.cert, &fx.key)];
    let (map, _) = build(&entries, &options(false, false), None).await?;

    let cfg = map
        .select(Some("example.com"))
        .ok_or("example.com must resolve")?;
    assert!(!cfg.ticketer.enabled(), "resumption disabled ⇒ no ticketer");
    assert!(!cfg.session_storage.can_cache(), "no server-side session cache either");
    Ok(())
}

/// mTLS domain never resumes, even with resumption enabled: no ticketer, no cache, so the
/// client certificate is verified on every connection.
#[tokio::test]
async fn mtls_config_disables_resumption_entirely() -> TestResult {
    let fx = fixture()?;
    let entries = vec![mtls_entry(Some("secure.example.com"), &fx.cert, &fx.key, &fx.client_ca)];
    let (map, report) = build(&entries, &options(true, false), None).await?;

    assert!(report.failed.is_empty(), "mTLS config must build");
    let cfg = map
        .select(Some("secure.example.com"))
        .ok_or("secure.example.com must resolve")?;
    assert!(!cfg.ticketer.enabled(), "mTLS config must not issue tickets");
    assert!(!cfg.session_storage.can_cache(), "mTLS config must not cache sessions");
    Ok(())
}

/// The stateless ticketer is one process-wide instance, so tickets stay decryptable
/// after a rebuild (certificate hot-reload).
#[tokio::test]
async fn ticketer_is_shared_across_rebuilds() -> TestResult {
    let fx = fixture()?;
    let entries = vec![entry(Some("example.com"), &fx.cert, &fx.key)];

    let (first, _) = build(&entries, &options(true, false), None).await?;
    let (second, _) = build(&entries, &options(true, false), Some(&first)).await?;

    let first_cfg = first
        .select(Some("example.com"))
        .ok_or("first build resolves")?;
    let second_cfg = second
        .select(Some("example.com"))
        .ok_or("second build resolves")?;
    assert!(
        Arc::ptr_eq(&first_cfg.ticketer, &second_cfg.ticketer),
        "ticketer must be one process-wide instance so tickets survive hot-reloads"
    );
    Ok(())
}
