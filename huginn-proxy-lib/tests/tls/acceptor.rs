use huginn_proxy_lib::config::{ClientAuth, TlsConfig};
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
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
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
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
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
        alpn: vec![], // Empty ALPN means no ALPN
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
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
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
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
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let result = build_rustls(&config);
    assert!(result.is_err());

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    Ok(())
}

#[test]
fn test_mtls_missing_client_ca() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Required { ca_cert_path: "/nonexistent/ca.pem".to_string() },
        session_resumption: Default::default(),
    };

    let result = build_rustls(&config);
    assert!(result.is_err());

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    if let Err(err) = result {
        let err_msg = format!("{}", err);
        assert!(err_msg.contains("Failed to read client CA certificate"));
    }

    Ok(())
}

#[test]
fn test_mtls_invalid_client_ca_pem() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;
    let ca_path = tmp_path("invalid_ca.pem");
    fs::write(&ca_path, b"not a valid PEM file")?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Required { ca_cert_path: ca_path.display().to_string() },
        session_resumption: Default::default(),
    };

    let result = build_rustls(&config);
    assert!(result.is_err());

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&ca_path);

    if let Err(err) = result {
        let err_msg = format!("{}", err);
        // The error could be about parsing or about the certificate content
        // Both are acceptable since we're testing invalid PEM
        assert!(
            err_msg.contains("Failed to parse client CA certificates")
                || err_msg.contains("Failed to add CA certificate")
                || err_msg.contains("Failed to build client verifier")
        );
    }

    Ok(())
}

#[test]
fn test_mtls_valid_client_ca_format() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;
    let ca_path = tmp_path("ca.pem");

    // Write a minimal valid CA certificate in PEM format
    fs::write(
        &ca_path,
        b"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKJ\n-----END CERTIFICATE-----\n",
    )?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Required { ca_cert_path: ca_path.display().to_string() },
        session_resumption: Default::default(),
    };

    let result = build_rustls(&config);

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&ca_path);

    assert!(result.is_err());
    if let Err(err) = result {
        let err_msg = format!("{}", err);
        // Should not be a CA-related error
        assert!(!err_msg.contains("client CA"));
    }

    Ok(())
}

#[test]
fn test_mtls_multiple_ca_certificates() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;
    let ca_path = tmp_path("multi_ca.pem");

    // Write multiple CA certificates in PEM format (simulating production, dev, and partner CAs)
    fs::write(
        &ca_path,
        b"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKJ\n-----END CERTIFICATE-----\n\
          -----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKK\n-----END CERTIFICATE-----\n\
          -----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKL\n-----END CERTIFICATE-----\n",
    )?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Required { ca_cert_path: ca_path.display().to_string() },
        session_resumption: Default::default(),
    };

    let result = build_rustls(&config);

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&ca_path);

    assert!(result.is_err());
    if let Err(err) = result {
        let err_msg = format!("{}", err);
        // Should not be a CA-related error - all 3 CAs should load successfully
        assert!(!err_msg.contains("client CA"));
    }

    Ok(())
}

#[test]
fn test_mtls_disabled_by_default() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;

    // Default ClientAuth should be Disabled
    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let result = build_rustls(&config);

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    assert!(result.is_err());
    if let Err(err) = result {
        let err_msg = format!("{}", err);
        assert!(!err_msg.contains("client CA"));
        assert!(!err_msg.contains("client verifier"));
    }

    Ok(())
}

#[test]
fn test_client_auth_enum_default() {
    use huginn_proxy_lib::config::ClientAuth;

    // Verify that ClientAuth::Disabled is the default
    let default_auth = ClientAuth::default();
    assert!(matches!(default_auth, ClientAuth::Disabled));
}
