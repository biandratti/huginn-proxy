use crate::helpers::{create_dummy_test_cert, create_valid_test_cert, tmp_path};
use huginn_proxy_lib::config::{ClientAuth, TlsConfig};
use huginn_proxy_lib::tls::build_tls_acceptor;
use std::fs;

#[test]
fn test_build_tls_acceptor_success() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    // With valid certs, this should succeed
    let result = build_tls_acceptor(&config);

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Should succeed with valid cert/key
    assert!(result.is_ok(), "build_tls_acceptor should succeed with valid certificates");
    Ok(())
}

#[test]
fn test_build_tls_acceptor_missing_cert() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: "/nonexistent/cert.pem".to_string(),
        key_path: "/nonexistent/key.pem".to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let result = build_tls_acceptor(&config);
    assert!(result.is_err());

    if let Err(err) = result {
        assert!(matches!(err, huginn_proxy_lib::error::ProxyError::Tls(_)));
    }
    Ok(())
}

#[test]
fn test_build_tls_acceptor_empty_alpn() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![], // Empty ALPN means no ALPN
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let result = build_tls_acceptor(&config);

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Should succeed with valid cert/key and empty ALPN
    assert!(result.is_ok(), "build_tls_acceptor should succeed with empty ALPN");
    Ok(())
}

#[test]
fn test_build_tls_acceptor_custom_alpn() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string()],
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let result = build_tls_acceptor(&config);

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Should succeed with valid cert/key and custom ALPN
    assert!(result.is_ok(), "build_tls_acceptor should succeed with custom ALPN");
    Ok(())
}

#[test]
fn test_build_tls_acceptor_invalid_pem() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    let result = build_tls_acceptor(&config);
    assert!(result.is_err());

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    Ok(())
}

#[test]
fn test_mtls_missing_client_ca() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_dummy_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Required { ca_cert_path: "/nonexistent/ca.pem".to_string() },
        session_resumption: Default::default(),
    };

    let result = build_tls_acceptor(&config);
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
    let (cert_path, key_path) = create_dummy_test_cert()?;
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

    let result = build_tls_acceptor(&config);
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
    let (cert_path, key_path) = create_valid_test_cert()?;
    let ca_path = tmp_path("ca.pem");

    // Generate a valid CA certificate using rcgen
    let ca_cert = rcgen::generate_simple_self_signed(vec!["ca.example.com".to_string()])?;
    fs::write(&ca_path, ca_cert.cert.pem())?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Required { ca_cert_path: ca_path.display().to_string() },
        session_resumption: Default::default(),
    };

    let result = build_tls_acceptor(&config);

    // Cleanup
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&ca_path);

    // Should succeed with valid cert/key and valid CA format
    assert!(result.is_ok(), "build_tls_acceptor should succeed with valid CA format");

    Ok(())
}

#[test]
fn test_mtls_multiple_ca_certificates() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let ca_path = tmp_path("multi_ca.pem");

    // Generate multiple valid CA certificates (simulating production, dev, and partner CAs)
    let ca1 = rcgen::generate_simple_self_signed(vec!["ca1.example.com".to_string()])?;
    let ca2 = rcgen::generate_simple_self_signed(vec!["ca2.example.com".to_string()])?;
    let ca3 = rcgen::generate_simple_self_signed(vec!["ca3.example.com".to_string()])?;

    let mut ca_pem = ca1.cert.pem();
    ca_pem.push_str(&ca2.cert.pem());
    ca_pem.push_str(&ca3.cert.pem());
    fs::write(&ca_path, ca_pem)?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Required { ca_cert_path: ca_path.display().to_string() },
        session_resumption: Default::default(),
    };

    let result = build_tls_acceptor(&config);

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&ca_path);

    // Should succeed with valid cert/key and multiple CAs
    assert!(
        result.is_ok(),
        "build_tls_acceptor should succeed with multiple CA certificates"
    );

    Ok(())
}

#[test]
fn test_mtls_disabled_by_default() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_dummy_test_cert()?;

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

    let result = build_tls_acceptor(&config);

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
