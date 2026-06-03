use crate::helpers::create_valid_test_cert;
use huginn_proxy_lib::config::{ClientAuth, TlsOptions};
use huginn_proxy_lib::tls::build_server_config;
use huginn_proxy_lib::tls::cert_source::{CertSource, StaticCertSource};
use huginn_proxy_lib::tls::cipher_suites::supported_cipher_suites;
use huginn_proxy_lib::tls::curves::supported_curves;

async fn build_acceptor_from_files(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    options: TlsOptions,
    alpn: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let source = CertSource::Static(StaticCertSource::load(cert_path, key_path).await?);
    let certs = source.current();
    build_server_config(
        certs.certs.clone(),
        certs.key.clone_key(),
        &alpn,
        &options,
        &ClientAuth::Disabled,
        &Default::default(),
    )?;
    Ok(())
}

#[tokio::test]
async fn test_different_cipher_suites_produce_different_configs(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let supported = supported_cipher_suites();

    let options1 = TlsOptions {
        cipher_suites: supported
            .iter()
            .filter(|s| s.starts_with("TLS13_"))
            .map(|s| s.to_string())
            .collect(),
        ..Default::default()
    };
    let options2 = TlsOptions {
        cipher_suites: supported
            .iter()
            .filter(|s| s.starts_with("TLS_ECDHE_"))
            .map(|s| s.to_string())
            .collect(),
        ..Default::default()
    };

    let result1 =
        build_acceptor_from_files(&cert_path, &key_path, options1.clone(), vec!["h2".to_string()])
            .await;
    let result2 =
        build_acceptor_from_files(&cert_path, &key_path, options2.clone(), vec!["h2".to_string()])
            .await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(result1.is_ok(), "should succeed with TLS 1.3 cipher suites");
    assert!(result2.is_ok(), "should succeed with TLS 1.2 cipher suites");
    assert_ne!(options1.cipher_suites, options2.cipher_suites);
    assert!(options1
        .cipher_suites
        .iter()
        .all(|s| s.starts_with("TLS13_")));
    assert!(options2
        .cipher_suites
        .iter()
        .all(|s| s.starts_with("TLS_ECDHE_")));

    Ok(())
}

#[tokio::test]
async fn test_different_curve_preferences_produce_different_configs(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let options1 =
        TlsOptions { curve_preferences: vec!["X25519".to_string()], ..Default::default() };
    let options2 =
        TlsOptions { curve_preferences: vec!["secp256r1".to_string()], ..Default::default() };

    let result1 =
        build_acceptor_from_files(&cert_path, &key_path, options1.clone(), vec!["h2".to_string()])
            .await;
    let result2 =
        build_acceptor_from_files(&cert_path, &key_path, options2.clone(), vec!["h2".to_string()])
            .await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(result1.is_ok(), "should succeed with X25519 curve");
    assert!(result2.is_ok(), "should succeed with secp256r1 curve");
    assert_ne!(options1.curve_preferences, options2.curve_preferences);
    assert_eq!(options1.curve_preferences, vec!["X25519".to_string()]);
    assert_eq!(options2.curve_preferences, vec!["secp256r1".to_string()]);

    Ok(())
}

#[tokio::test]
async fn test_combined_cipher_and_curve_configs(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let supported_suites = supported_cipher_suites();
    let supported_curves_list = supported_curves();

    let options = TlsOptions {
        cipher_suites: vec![supported_suites[0].to_string(), supported_suites[1].to_string()],
        curve_preferences: vec![supported_curves_list[0].to_string()],
        ..Default::default()
    };

    let result =
        build_acceptor_from_files(&cert_path, &key_path, options.clone(), vec!["h2".to_string()])
            .await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(result.is_ok(), "should succeed with combined cipher and curve configs");
    assert_eq!(options.cipher_suites.len(), 2);
    assert_eq!(options.curve_preferences.len(), 1);

    Ok(())
}
