//! Per-SNI `ServerConfig` build + selection tests for [`build_server_crypto`].
//!
//! Cover huginn's resolution model preserved on the per-SNI map (exact → wildcard
//! → catch-all + `sni_strict`), best-effort carry-forward, and the rpxy resumption
//! policy: non-mTLS configs issue stateless tickets from one shared ticketer while
//! mTLS configs never resume so the client cert is verified on every connection.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use huginn_certs::server_crypto::build_client_root_store;
use huginn_certs::{
    build_server_crypto, CertEntry, CryptoFileSource, ServerCryptoMap, TlsBuildOptions,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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

#[tokio::test]
async fn restricted_curve_preferences_still_build() -> TestResult {
    use huginn_certs::kx_groups::{resolve_kx_groups, KxGroupName};

    let names = [KxGroupName::X25519MlKem768, KxGroupName::X25519, KxGroupName::Secp256r1];
    assert_eq!(resolve_kx_groups(&names).len(), 3, "all three typed groups map");

    let fx = fixture()?;
    let opts = TlsBuildOptions {
        curve_preferences: vec![KxGroupName::X25519MlKem768, KxGroupName::X25519],
        ..options(true, false)
    };
    let entries = vec![entry(Some("api.example.com"), &fx.cert, &fx.key)];
    let (map, report) = build(&entries, &opts, None).await?;

    assert!(report.failed.is_empty(), "a curve-restricted config must build");
    assert!(map.resolves_for(Some("api.example.com")), "the restricted config must resolve");
    Ok(())
}

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

/// PEM for a private key belonging to some *other* certificate.
fn foreign_key_pem() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    Ok(rcgen::generate_simple_self_signed(vec!["other.example.com".to_string()])?
        .signing_key
        .serialize_pem())
}

#[tokio::test]
async fn several_keys_in_one_file_picks_the_matching_one() -> TestResult {
    let fx = fixture()?;
    let foreign = foreign_key_pem()?;
    let matching = std::fs::read_to_string(&fx.key)?;

    for (name, contents) in [
        ("matching-first.key", format!("{matching}{foreign}")),
        ("matching-last.key", format!("{foreign}{matching}")),
    ] {
        let key_path = fx.key.with_file_name(name);
        std::fs::write(&key_path, contents)?;
        let entries = vec![entry(Some("api.example.com"), &fx.cert, &key_path)];
        let (map, report) = build(&entries, &options(true, false), None).await?;

        assert!(report.failed.is_empty(), "{name}: the matching key must be found");
        assert!(map.resolves_for(Some("api.example.com")), "{name}: the config must resolve");
    }
    Ok(())
}

#[tokio::test]
async fn a_key_file_without_the_matching_key_is_rejected() -> TestResult {
    let fx = fixture()?;
    let key_path = fx.key.with_file_name("foreign-only.key");
    std::fs::write(&key_path, foreign_key_pem()?)?;

    let entries = vec![entry(Some("api.example.com"), &fx.cert, &key_path)];
    let (map, report) = build(&entries, &options(true, false), None).await?;

    assert_eq!(report.failed.len(), 1, "a key from another cert must not be accepted");
    assert!(report.loaded.is_empty(), "nothing should load");
    assert!(!map.resolves_for(Some("api.example.com")), "the domain must not serve");
    Ok(())
}

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

/// An empty (but existing) client-CA bundle next to the fixture: the config loader only checks
/// that the path exists, so this is what reaches the builder in practice.
fn empty_client_ca(fx: &Fixture) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let path = fx
        .cert
        .parent()
        .ok_or("fixture cert has no parent dir")?
        .join("empty-ca.pem");
    std::fs::write(&path, b"")?;
    Ok(path)
}

fn is_reject(map: &ServerCryptoMap, sni: Option<&str>) -> bool {
    map.select(sni)
        .is_some_and(|crypto| Arc::ptr_eq(&crypto.config, &map.reject_config()))
}

/// Both the previous plain config and the catch-all would answer without a client
/// certificate, which is what the domain just asked to require.
#[tokio::test]
async fn failed_mtls_never_falls_back_to_a_plain_config() -> TestResult {
    let fx = fixture()?;
    let plain = vec![
        entry(None, &fx.cert, &fx.key),
        entry(Some("admin.example.com"), &fx.cert, &fx.key),
    ];
    let (first, first_report) = build(&plain, &options(true, false), None).await?;
    assert!(first_report.failed.is_empty(), "initial plain build succeeds");

    // The operator adds client_ca_path, pointing at a file that exists but holds no certificate.
    let broken_ca = empty_client_ca(&fx)?;
    let with_mtls = vec![
        entry(None, &fx.cert, &fx.key),
        mtls_entry(Some("admin.example.com"), &fx.cert, &fx.key, &broken_ca),
    ];
    let (second, second_report) = build(&with_mtls, &options(true, false), Some(&first)).await?;

    assert_eq!(second_report.failed, vec!["admin.example.com".to_string()]);
    assert!(
        is_reject(&second, Some("admin.example.com")),
        "handshakes for the domain are rejected"
    );
    assert!(!is_reject(&second, None), "other domains are unaffected");
    Ok(())
}

/// At startup there is nothing to inherit, and an empty slot falls through to the
/// catch-all, so the domain has to be parked on the reject sentinel.
#[tokio::test]
async fn failed_mtls_at_startup_rejects_instead_of_serving_the_catch_all() -> TestResult {
    let fx = fixture()?;
    let broken_ca = empty_client_ca(&fx)?;
    let entries = vec![
        entry(None, &fx.cert, &fx.key),
        mtls_entry(Some("admin.example.com"), &fx.cert, &fx.key, &broken_ca),
    ];
    let (map, report) = build(&entries, &options(true, false), None).await?;

    assert_eq!(report.failed, vec!["admin.example.com".to_string()]);
    assert!(
        is_reject(&map, Some("admin.example.com")),
        "no catch-all fallback for an mTLS domain"
    );
    assert!(
        map.resolves_for(Some("other.example.com")),
        "unrelated SNI still gets the catch-all"
    );
    Ok(())
}

/// Carry-forward still applies when it cannot weaken anything: keeping a config that
/// already required a client certificate is stale, not unauthenticated.
#[tokio::test]
async fn failed_mtls_keeps_a_previous_mtls_config() -> TestResult {
    let fx = fixture()?;
    let good = vec![mtls_entry(Some("admin.example.com"), &fx.cert, &fx.key, &fx.client_ca)];
    let (first, first_report) = build(&good, &options(true, false), None).await?;
    assert!(first_report.failed.is_empty(), "initial mTLS build succeeds");

    let missing = Path::new("/nonexistent/huginn-test/missing.pem");
    let bad = vec![mtls_entry(Some("admin.example.com"), missing, missing, &fx.client_ca)];
    let (second, second_report) = build(&bad, &options(true, false), Some(&first)).await?;

    assert_eq!(second_report.failed.len(), 1, "the failed cert is reported");
    assert!(
        !is_reject(&second, Some("admin.example.com")),
        "the last-good mTLS config is kept"
    );
    assert!(
        second
            .select(Some("admin.example.com"))
            .is_some_and(|crypto| crypto.is_mutual_tls),
        "and it still enforces client authentication"
    );
    Ok(())
}

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

/// Even with resumption enabled, so the client certificate is verified on every connection.
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

/// A CA and one leaf it signed, in the shapes the handshake tests need: PEM to write out
/// as config material, DER to hand straight to rustls.
struct SignedPair {
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    leaf_pem: String,
    leaf_key_pem: String,
    leaf_der: CertificateDer<'static>,
    leaf_key: PrivateKeyDer<'static>,
}

fn signed_pair(
    ca_name: &str,
    leaf_name: &str,
    purpose: ExtendedKeyUsagePurpose,
) -> Result<SignedPair, Box<dyn std::error::Error + Send + Sync>> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(vec![ca_name.to_string()])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key)?;

    let leaf_key = KeyPair::generate()?;
    let mut leaf_params = CertificateParams::new(vec![leaf_name.to_string()])?;
    leaf_params.extended_key_usages = vec![purpose];
    let leaf = leaf_params.signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))?;

    Ok(SignedPair {
        ca_pem: ca.pem(),
        ca_der: ca.der().clone(),
        leaf_pem: leaf.pem(),
        leaf_key_pem: leaf_key.serialize_pem(),
        leaf_der: leaf.der().clone(),
        leaf_key: PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
    })
}

/// One domain served twice: with and without a client verifier, from the same server
/// certificate, so the two handshakes differ only in client authentication.
struct HandshakeFixture {
    _dir: tempfile::TempDir,
    mtls: Arc<ServerConfig>,
    plain: Arc<ServerConfig>,
    /// The CA the client must trust to accept the server certificate.
    server_ca: CertificateDer<'static>,
    /// A client identity signed by the CA the mTLS domain was configured with.
    client: SignedPair,
}

async fn handshake_fixture() -> Result<HandshakeFixture, Box<dyn std::error::Error + Send + Sync>> {
    ensure_crypto_provider();
    let dir = tempfile::tempdir()?;
    let server = signed_pair("server-ca", "localhost", ExtendedKeyUsagePurpose::ServerAuth)?;
    let client = signed_pair("client-ca", "client.example", ExtendedKeyUsagePurpose::ClientAuth)?;

    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");
    let client_ca = dir.path().join("client-ca.crt");
    std::fs::write(&cert, &server.leaf_pem)?;
    std::fs::write(&key, &server.leaf_key_pem)?;
    std::fs::write(&client_ca, &client.ca_pem)?;

    let opts = options(true, false);
    let (with_mtls, mtls_report) =
        build(&[mtls_entry(Some("localhost"), &cert, &key, &client_ca)], &opts, None).await?;
    let (without_mtls, plain_report) =
        build(&[entry(Some("localhost"), &cert, &key)], &opts, None).await?;
    if !mtls_report.failed.is_empty() || !plain_report.failed.is_empty() {
        return Err("both configs must build".into());
    }

    Ok(HandshakeFixture {
        _dir: dir,
        mtls: with_mtls
            .select(Some("localhost"))
            .ok_or("the mTLS domain must resolve")?
            .config,
        plain: without_mtls
            .select(Some("localhost"))
            .ok_or("the plain domain must resolve")?
            .config,
        server_ca: server.ca_der,
        client,
    })
}

fn client_config(
    trusted: &CertificateDer<'static>,
    identity: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
) -> Result<ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut roots = RootCertStore::empty();
    roots.add(trusted.clone())?;
    let builder = ClientConfig::builder().with_root_certificates(roots);
    Ok(match identity {
        Some((cert, key)) => builder.with_client_auth_cert(vec![cert], key)?,
        None => builder.with_no_client_auth(),
    })
}

/// Run one handshake over an in-memory pipe and report how the *server* saw it, which is
/// where client authentication is decided: under TLS 1.3 the client finishes before the
/// server's verdict reaches it, so only this side is conclusive.
async fn handshake(server: Arc<ServerConfig>, client: ClientConfig) -> std::io::Result<()> {
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let acceptor = TlsAcceptor::from(server);
    let connector = TlsConnector::from(Arc::new(client));
    let name = ServerName::try_from("localhost").map_err(std::io::Error::other)?;

    let (accepted, _connected) =
        tokio::join!(acceptor.accept(server_io), connector.connect(name, client_io));
    accepted.map(|_| ())
}

/// `is_mutual_tls` is read off the configuration, so it keeps saying `true` even if the
/// verifier stops being attached. Only a handshake tells the two apart.
#[tokio::test]
async fn mtls_config_turns_away_a_client_without_a_certificate() -> TestResult {
    let fx = handshake_fixture().await?;

    let rejected = handshake(fx.mtls, client_config(&fx.server_ca, None)?).await;
    assert!(rejected.is_err(), "no client certificate must not complete the handshake");

    // Control: the same client against the same server certificate, minus the verifier.
    handshake(fx.plain, client_config(&fx.server_ca, None)?).await?;
    Ok(())
}

#[tokio::test]
async fn mtls_config_admits_a_client_signed_by_the_configured_ca() -> TestResult {
    let fx = handshake_fixture().await?;
    let identity = (fx.client.leaf_der.clone(), fx.client.leaf_key.clone_key());

    handshake(fx.mtls, client_config(&fx.server_ca, Some(identity))?).await?;
    Ok(())
}

/// The verifier honours the configured trust anchors, rather than accepting whatever
/// certificate is presented.
#[tokio::test]
async fn mtls_config_turns_away_a_client_signed_by_another_ca() -> TestResult {
    let fx = handshake_fixture().await?;
    let stranger =
        signed_pair("other-ca", "intruder.example", ExtendedKeyUsagePurpose::ClientAuth)?;
    let identity = (stranger.leaf_der, stranger.leaf_key);

    let rejected = handshake(fx.mtls, client_config(&fx.server_ca, Some(identity))?).await;
    assert!(rejected.is_err(), "a certificate from an untrusted CA must be refused");
    Ok(())
}

/// A CA cert whose Subject Key Identifier extension is emitted (rcgen writes it for
/// `IsCa::Ca`), so the client-CA dedup keys on SKID rather than falling back to DER.
fn ca_cert(name: &str, key: &KeyPair) -> Result<rcgen::Certificate, rcgen::Error> {
    let mut params = CertificateParams::new(vec![name.to_string()])?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.self_signed(key)
}

#[test]
fn client_root_store_dedups_identical_der() -> TestResult {
    let key = KeyPair::generate()?;
    let der = ca_cert("client-ca", &key)?.der().clone();

    let single = build_client_root_store(std::slice::from_ref(&der), "test")?;
    let duplicated = build_client_root_store(&[der.clone(), der], "test")?;

    assert_eq!(single.roots.len(), 1, "one anchor stays one");
    assert_eq!(duplicated.roots.len(), 1, "a repeated DER anchor must dedup to one");
    Ok(())
}

/// Two encodings of the same CA key share a Subject Key Identifier, so they collapse to
/// one anchor: something byte dedup alone cannot do.
#[test]
fn client_root_store_dedups_same_key_across_different_der() -> TestResult {
    let key = KeyPair::generate()?;
    let der_one = ca_cert("ca-one.example", &key)?.der().clone();
    let der_two = ca_cert("ca-two.example", &key)?.der().clone();

    assert_ne!(
        der_one.as_ref(),
        der_two.as_ref(),
        "the two certs must differ at the byte level"
    );

    let store = build_client_root_store(&[der_one, der_two], "test")?;
    assert_eq!(store.roots.len(), 1, "same CA key (shared SKID) must dedup across encodings");
    Ok(())
}
