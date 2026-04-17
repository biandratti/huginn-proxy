use crate::helpers::{create_valid_test_cert, generate_dummy_test_cert_der};
use huginn_proxy_lib::config::{ClientAuth, TlsConfig, TlsOptions};
use huginn_proxy_lib::tls::build_cert_reloader;

#[tokio::test]
async fn test_build_cert_reloader() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let config = TlsConfig {
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string()],
        options: TlsOptions::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    // This should succeed in creating the reloader service with valid certificates
    let result = build_cert_reloader(&config, true, 60).await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Should succeed - reloader service is created with valid certificates
    let rx = match result {
        Ok(rx) => rx,
        Err(e) => panic!("build_cert_reloader should succeed with valid certificates: {e}"),
    };
    let initial_value = rx.borrow();
    let certs_keys = match initial_value.as_ref() {
        Some(certs_keys) => certs_keys,
        None => panic!("initial value should be Some"),
    };

    let alpn = vec!["h2".to_string()];
    let options = TlsOptions::default();
    // With valid certs, this should also succeed
    let acceptor_result =
        certs_keys.build_tls_acceptor(&alpn, &options, &config.session_resumption);
    assert!(
        acceptor_result.is_ok(),
        "build_tls_acceptor should succeed with valid certificates"
    );

    Ok(())
}

#[tokio::test]
async fn test_build_cert_reloader_missing_files(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = TlsConfig {
        cert_path: "/nonexistent/cert.pem".to_string(),
        key_path: "/nonexistent/key.pem".to_string(),
        alpn: vec![],
        options: TlsOptions::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    // Should fail because certificates must exist at startup
    let result = build_cert_reloader(&config, true, 60).await;
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_server_certs_keys_build_tls_acceptor(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use huginn_proxy_lib::tls::ServerCertsKeys;

    let (cert, key) = generate_dummy_test_cert_der();
    let certs = vec![cert];

    let server_certs_keys = ServerCertsKeys { certs, key };
    let alpn = vec!["h2".to_string()];
    let options = TlsOptions::default();

    // This will fail because certs/key are invalid, but we test the function exists
    let result = server_certs_keys.build_tls_acceptor(&alpn, &options, &Default::default());
    assert!(result.is_err());
    Ok(())
}
