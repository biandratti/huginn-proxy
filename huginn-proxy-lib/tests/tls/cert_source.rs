use std::sync::Arc;

use crate::helpers::{generate_dummy_test_cert_der, generate_valid_test_cert_der};
use huginn_proxy_lib::config::{ClientAuth, TlsConfig, TlsOptions};
use huginn_proxy_lib::tls::{
    build_server_config, build_tls_acceptor, cert_chain_hash, DynamicCertResolver, ServerCertsKeys,
};
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
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let acceptor = build_tls_acceptor(&config, Arc::new(DynamicCertResolver::new(false))).await?;
    let _ = acceptor.load();
    Ok(())
}

#[test]
fn build_server_config_rejects_invalid_certs(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = generate_dummy_test_cert_der();
    let server_certs_keys = ServerCertsKeys { certs: vec![cert], key };
    let alpn = vec!["h2".to_string()];
    let options = TlsOptions::default();

    let result = build_server_config(
        server_certs_keys.certs.clone(),
        server_certs_keys.key.clone_key(),
        &alpn,
        &options,
        &ClientAuth::Disabled,
        &Default::default(),
    );
    assert!(result.is_err(), "dummy DER bytes must fail to build a ServerConfig");
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

#[tokio::test]
async fn cipher_suites_applied_on_initial_build(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = generate_valid_test_cert_der()?;

    let options = TlsOptions {
        cipher_suites: vec!["TLS13_AES_128_GCM_SHA256".to_string()],
        ..Default::default()
    };
    let server = build_server_config(
        vec![cert],
        key,
        &[],
        &options,
        &ClientAuth::Disabled,
        &Default::default(),
    )?;

    assert_eq!(
        cipher_suites_of(&server),
        vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
        "build_server_config must apply the configured cipher suites, not the provider defaults"
    );
    Ok(())
}

#[tokio::test]
async fn cert_chain_hash_changes_when_certificate_chain_changes(
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
