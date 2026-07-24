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

/// A restricted protocol-version list is accepted by the builder and still yields a
/// resolvable config (the build path applies `with_protocol_versions` instead of the
/// safe defaults).
#[tokio::test]
async fn restricted_protocol_version_still_builds() -> TestResult {
    let fx = fixture()?;
    let opts = TlsBuildOptions {
        protocol_versions: vec![&tokio_rustls::rustls::version::TLS13],
        ..options(true, false)
    };
    let entries = vec![entry(Some("api.example.com"), &fx.cert, &fx.key)];
    let (map, report) = build(&entries, &opts, None).await?;

    assert!(report.failed.is_empty(), "a TLS 1.3-only config must build");
    assert!(map.resolves_for(Some("api.example.com")), "the restricted config must resolve");
    Ok(())
}

/// Explicit curve preferences (including the post-quantum hybrid) resolve to
/// key-exchange groups and still build a resolvable config; unknown names are
/// dropped.
#[tokio::test]
async fn restricted_curve_preferences_still_build() -> TestResult {
    use huginn_certs::kx_groups::resolve_kx_groups;

    // Mapping: known names resolve, unknown (and the unavailable secp521r1) are dropped.
    let names = vec![
        "X25519MLKEM768".to_string(),
        "X25519".to_string(),
        "secp256r1".to_string(),
        "secp521r1".to_string(),
        "bogus".to_string(),
    ];
    assert_eq!(resolve_kx_groups(&names).len(), 3, "only the 3 available groups map");

    let fx = fixture()?;
    let opts = TlsBuildOptions {
        curve_preferences: vec!["X25519MLKEM768".to_string(), "X25519".to_string()],
        ..options(true, false)
    };
    let entries = vec![entry(Some("api.example.com"), &fx.cert, &fx.key)];
    let (map, report) = build(&entries, &opts, None).await?;

    assert!(report.failed.is_empty(), "a curve-restricted config must build");
    assert!(map.resolves_for(Some("api.example.com")), "the restricted config must resolve");
    Ok(())
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
    assert!(!cfg.is_mutual_tls, "a plain domain must not be flagged as mutual TLS");
    assert!(cfg.config.ticketer.enabled(), "non-mTLS config must issue stateless tickets");
    assert!(
        !cfg.config.session_storage.can_cache(),
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
    assert!(!cfg.config.ticketer.enabled(), "resumption disabled ⇒ no ticketer");
    assert!(!cfg.config.session_storage.can_cache(), "no server-side session cache either");
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
    assert!(cfg.is_mutual_tls, "a client-CA domain must be flagged as mutual TLS");
    assert!(!cfg.config.ticketer.enabled(), "mTLS config must not issue tickets");
    assert!(!cfg.config.session_storage.can_cache(), "mTLS config must not cache sessions");
    Ok(())
}

/// Client auth is per-domain, not listener-wide: in one map, only the mTLS domain
/// disables resumption while a plain domain alongside it still issues tickets.
#[tokio::test]
async fn mtls_is_per_domain_not_listener_wide() -> TestResult {
    let fx = fixture()?;
    let entries = vec![
        entry(Some("plain.example.com"), &fx.cert, &fx.key),
        mtls_entry(Some("secure.example.com"), &fx.cert, &fx.key, &fx.client_ca),
    ];
    let (map, report) = build(&entries, &options(true, false), None).await?;

    assert!(report.failed.is_empty(), "both the plain and mTLS configs must build");

    let plain = map
        .select(Some("plain.example.com"))
        .ok_or("plain domain must resolve")?;
    assert!(!plain.is_mutual_tls, "plain domain is not mutual TLS");
    assert!(plain.config.ticketer.enabled(), "non-mTLS domain still resumes via tickets");

    let secure = map
        .select(Some("secure.example.com"))
        .ok_or("secure domain must resolve")?;
    assert!(secure.is_mutual_tls, "the client-CA domain is mutual TLS");
    assert!(!secure.config.ticketer.enabled(), "mTLS domain in the same map never resumes");
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
        Arc::ptr_eq(&first_cfg.config.ticketer, &second_cfg.config.ticketer),
        "ticketer must be one process-wide instance so tickets survive hot-reloads"
    );
    Ok(())
}
