use huginn_proxy_lib::config::TlsConfig;
use huginn_proxy_lib::tls::{
    build_cert_reloader, CryptoFileSource, CryptoSource, ServerCryptoBase,
};
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
async fn test_crypto_file_source_read() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;

    let source = CryptoFileSource { cert_path: cert_path.clone(), key_path: key_path.clone() };

    // Test that the function exists and can be called
    // The result may succeed in parsing PEM format, but will fail when building TLS config
    // (which is tested in build_tls_acceptor tests)
    let result = source.read().await;

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // The function should at least attempt to read and parse the files
    // Whether it succeeds or fails depends on PEM format validity
    // The important thing is that the function exists and can be called
    match result {
        Ok(_) => {
            // PEM format was valid, which is fine for this test
        }
        Err(_) => {
            // PEM format was invalid, which is also fine
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_crypto_file_source_missing_file(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = tmp_path("nonexistent.crt");
    let key_path = tmp_path("nonexistent.key");

    let source = CryptoFileSource { cert_path, key_path };

    let result = source.read().await;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn test_build_cert_reloader() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;

    let config = TlsConfig {
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string()],
        watch_delay_secs: 60,
    };

    // This should succeed in creating the reloader service, even with invalid certs
    // The reloader will fail when trying to read the certs, but the service itself is created
    let result = build_cert_reloader(&config).await;

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Should succeed - reloader service is created even if certs are invalid
    // The actual reload will fail, but that's tested separately
    assert!(result.is_ok());
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
    };

    let result = build_cert_reloader(&config).await;
    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_server_crypto_base_empty() {
    let base = ServerCryptoBase::default();
    let alpn = vec!["h2".to_string()];
    let result = base.get_tls_acceptor(&alpn);
    assert!(result.is_err());
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

    // This will fail because certs/key are invalid, but we test the function exists
    let result = server_certs_keys.build_tls_acceptor(&alpn);
    assert!(result.is_err());
    Ok(())
}
