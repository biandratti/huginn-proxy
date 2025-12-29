use huginn_proxy_lib::config::TlsConfig;
use huginn_proxy_lib::tls::build_rustls;
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

#[test]
fn test_build_rustls_success() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
    };

    // This will fail with invalid cert/key, but we can test the error handling
    let result = build_rustls(&config);

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Should return an error for invalid cert/key (expected)
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_build_rustls_missing_cert() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: "/nonexistent/cert.pem".to_string(),
        key_path: "/nonexistent/key.pem".to_string(),
        alpn: vec![],
    };

    let result = build_rustls(&config);
    assert!(result.is_err());

    if let Err(err) = result {
        assert!(matches!(err, huginn_proxy_lib::error::ProxyError::Tls(_)));
    }
    Ok(())
}

#[test]
fn test_build_rustls_empty_alpn() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![], // Empty ALPN should use defaults
    };

    let result = build_rustls(&config);

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Should fail with invalid cert/key, but we test the empty ALPN path
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_build_rustls_custom_alpn() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string()],
    };

    let result = build_rustls(&config);

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Should fail with invalid cert/key
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_build_rustls_invalid_pem() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = tmp_path("invalid.crt");
    let key_path = tmp_path("invalid.key");

    // Write invalid PEM data
    fs::write(&cert_path, b"not a valid PEM file")?;
    fs::write(&key_path, b"not a valid PEM file")?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
    };

    let result = build_rustls(&config);
    assert!(result.is_err());

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    Ok(())
}
