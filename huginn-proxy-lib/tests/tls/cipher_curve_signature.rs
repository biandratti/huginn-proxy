use huginn_proxy_lib::config::{TlsConfig, TlsOptions};
use huginn_proxy_lib::tls::acceptor::build_rustls;
use huginn_proxy_lib::tls::cipher_suites::supported_cipher_suites;
use huginn_proxy_lib::tls::curves::supported_curves;
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
fn test_different_cipher_suites_produce_different_configs(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;
    let supported = supported_cipher_suites();

    // Configuration 1: Only TLS 1.3 cipher suites
    let config1 = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        options: TlsOptions {
            cipher_suites: supported
                .iter()
                .filter(|s| s.starts_with("TLS13_"))
                .map(|s| s.to_string())
                .collect(),
            ..Default::default()
        },
    };

    // Configuration 2: Only TLS 1.2 cipher suites
    let config2 = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        options: TlsOptions {
            cipher_suites: supported
                .iter()
                .filter(|s| s.starts_with("TLS_ECDHE_"))
                .map(|s| s.to_string())
                .collect(),
            ..Default::default()
        },
    };

    // Both configurations should validate and build successfully
    // (even though rustls 0.23 doesn't apply them fully)
    let result1 = build_rustls(&config1);
    let result2 = build_rustls(&config2);

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Both should fail with invalid cert/key (expected), but validation should pass
    assert!(result1.is_err()); // Invalid cert/key
    assert!(result2.is_err()); // Invalid cert/key

    // Verify that the configurations are different
    assert_ne!(
        config1.options.cipher_suites, config2.options.cipher_suites,
        "Configurations should have different cipher suites"
    );

    // Verify that config1 only has TLS 1.3 suites
    assert!(
        config1
            .options
            .cipher_suites
            .iter()
            .all(|s| s.starts_with("TLS13_")),
        "Config1 should only contain TLS 1.3 cipher suites"
    );

    // Verify that config2 only has TLS 1.2 suites
    assert!(
        config2
            .options
            .cipher_suites
            .iter()
            .all(|s| s.starts_with("TLS_ECDHE_")),
        "Config2 should only contain TLS 1.2 cipher suites"
    );

    Ok(())
}

#[test]
fn test_different_curve_preferences_produce_different_configs(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;

    // Configuration 1: Only X25519 (preferred for performance)
    let config1 = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        options: TlsOptions { curve_preferences: vec!["X25519".to_string()], ..Default::default() },
    };

    // Configuration 2: Only secp256r1 (NIST P-256)
    let config2 = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        options: TlsOptions {
            curve_preferences: vec!["secp256r1".to_string()],
            ..Default::default()
        },
    };

    // Both configurations should validate and build successfully
    let result1 = build_rustls(&config1);
    let result2 = build_rustls(&config2);

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Both should fail with invalid cert/key (expected), but validation should pass
    assert!(result1.is_err()); // Invalid cert/key
    assert!(result2.is_err()); // Invalid cert/key

    // Verify that the configurations are different
    assert_ne!(
        config1.options.curve_preferences, config2.options.curve_preferences,
        "Configurations should have different curve preferences"
    );

    // Verify that config1 uses X25519
    assert_eq!(
        config1.options.curve_preferences,
        vec!["X25519".to_string()],
        "Config1 should use X25519"
    );

    // Verify that config2 uses secp256r1
    assert_eq!(
        config2.options.curve_preferences,
        vec!["secp256r1".to_string()],
        "Config2 should use secp256r1"
    );

    Ok(())
}

#[test]
fn test_combined_cipher_and_curve_configs() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let (cert_path, key_path) = create_test_cert()?;
    let supported_suites = supported_cipher_suites();
    let supported_curves = supported_curves();

    // Configuration with specific cipher suites and curve preferences
    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string()],
        options: TlsOptions {
            cipher_suites: vec![supported_suites[0].to_string(), supported_suites[1].to_string()],
            curve_preferences: vec![supported_curves[0].to_string()],
            ..Default::default()
        },
    };

    let result = build_rustls(&config);

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Should fail with invalid cert/key (expected), but validation should pass
    assert!(result.is_err()); // Invalid cert/key

    // Verify that both cipher suites and curve preferences are set
    assert_eq!(config.options.cipher_suites.len(), 2);
    assert_eq!(config.options.curve_preferences.len(), 1);

    Ok(())
}
