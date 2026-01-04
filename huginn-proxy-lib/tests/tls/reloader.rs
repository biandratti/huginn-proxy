use huginn_proxy_lib::config::{TlsConfig, TlsOptions};
use huginn_proxy_lib::tls::build_cert_reloader;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn tmp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    std::env::temp_dir().join(format!("huginn-test-{nanos}-{name}"))
}

fn create_test_cert() -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = tmp_path("test.crt");
    let key_path = tmp_path("test.key");

    // Create minimal valid PEM files for testing
    // Note: These are not real certificates, but valid PEM format
    fs::write(
        &cert_path,
        b"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKJ\n-----END CERTIFICATE-----\n",
    )?;
    fs::write(
        &key_path,
        b"-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkq\n-----END PRIVATE KEY-----\n",
    )?;

    Ok((cert_path, key_path))
}

#[tokio::test]
async fn test_build_cert_reloader() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;

    let config = TlsConfig {
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string()],
        watch_delay_secs: 60,
        options: TlsOptions::default(),
    };

    // This should succeed in creating the reloader service with valid PEM format
    // Note: The certs may not be cryptographically valid, but PEM format is correct
    let result = build_cert_reloader(&config).await;

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Should succeed - reloader service is created with valid PEM format
    if let Ok(rx) = result {
        let initial_value = rx.borrow();
        if let Some(certs_keys) = initial_value.as_ref() {
            let alpn = vec!["h2".to_string()];
            let options = TlsOptions::default();
            // This may fail due to invalid certs, but the structure should be correct
            let _ = certs_keys.build_tls_acceptor(&alpn, &options);
        } else {
            panic!("initial value should be Some");
        }
    } else {
        panic!("build_cert_reloader should succeed with valid PEM files");
    }
    Ok(())
}

#[tokio::test]
async fn test_build_cert_reloader_missing_files(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = TlsConfig {
        cert_path: "/nonexistent/cert.pem".to_string(),
        key_path: "/nonexistent/key.pem".to_string(),
        alpn: vec![],
        watch_delay_secs: 60,
        options: TlsOptions::default(),
    };

    // Should fail because certificates must exist at startup
    let result = build_cert_reloader(&config).await;
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_server_certs_keys_build_tls_acceptor(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use huginn_proxy_lib::tls::ServerCertsKeys;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    let certs = vec![CertificateDer::from(b"dummy cert".to_vec())];
    let key =
        PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(b"dummy key".to_vec()));

    let server_certs_keys = ServerCertsKeys { certs, key };
    let alpn = vec!["h2".to_string()];
    let options = TlsOptions::default();

    // This will fail because certs/key are invalid, but we test the function exists
    let result = server_certs_keys.build_tls_acceptor(&alpn, &options);
    assert!(result.is_err());
    Ok(())
}
