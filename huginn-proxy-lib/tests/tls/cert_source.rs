use std::sync::Arc;

use super::build_acceptor;
use huginn_proxy_lib::config::{TlsConfig, TlsOptions};
use huginn_proxy_lib::tls::{build_tls_acceptor, cert_chain_hash, DynamicCertResolver};
use tokio_rustls::rustls::{CipherSuite, ServerConfig};

/// `build_tls_acceptor` builds a working acceptor from a populated
/// `DynamicCertResolver`. Cert rotation happens inside the resolver via
/// `DynamicCertResolver::update()` (driven by the config reload path in
/// `proxy/reload.rs`), so the acceptor is built once and never swapped.
#[tokio::test]
async fn build_tls_acceptor_produces_usable_acceptor(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = TlsConfig {
        alpn: vec![],
        options: TlsOptions::default(),
        client_auth: None,
        session_resumption: Default::default(),
    };

    let acceptor =
        build_tls_acceptor(&config, Arc::new(DynamicCertResolver::new(false)), false).await?;
    // Acceptor must have been built successfully and be loadable.
    let _ = acceptor.load();
    Ok(())
}

fn cipher_suites_of(server: &ServerConfig) -> Vec<CipherSuite> {
    server
        .crypto_provider()
        .cipher_suites
        .iter()
        .map(|s| s.suite())
        .collect()
}

#[test]
fn cipher_suites_applied_on_initial_build() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let options = TlsOptions {
        cipher_suites: vec!["TLS13_AES_128_GCM_SHA256".to_string()],
        ..Default::default()
    };
    let acceptor = build_acceptor(&[], &options, None, false)?;

    assert_eq!(
        cipher_suites_of(acceptor.config()),
        vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
        "the resolver acceptor must apply the configured cipher suites, not the provider defaults"
    );
    Ok(())
}

#[test]
fn cert_chain_hash_changes_when_certificate_chain_changes(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rustls_pki_types::CertificateDer;

    let key_a = rcgen::generate_simple_self_signed(vec!["a.test".to_string()])?;
    let key_b = rcgen::generate_simple_self_signed(vec!["b.test".to_string()])?;

    let der_a: CertificateDer<'static> = key_a.cert.der().clone();
    let der_b: CertificateDer<'static> = key_b.cert.der().clone();

    let hash_a_first = cert_chain_hash(std::slice::from_ref(&der_a));
    let hash_a_second = cert_chain_hash(std::slice::from_ref(&der_a));
    let hash_b = cert_chain_hash(std::slice::from_ref(&der_b));

    assert_eq!(hash_a_first, hash_a_second, "same chain must produce a stable hash");
    assert_ne!(hash_a_first, hash_b, "different chains must produce different hashes");
    Ok(())
}
