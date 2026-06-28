use super::build_acceptor;
use crate::helpers::tmp_path;
use huginn_proxy_lib::config::{ClientAuth, TlsOptions};
use std::fs;

/// Build an acceptor through the resolver path with default TLS options, exercising
/// ALPN and client-auth wiring. Cert resolution itself is covered by `cert_resolver`.
fn build_with(
    alpn: Vec<String>,
    client_auth: Option<ClientAuth>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    build_acceptor(&alpn, &TlsOptions::default(), client_auth.as_ref(), false)?;
    Ok(())
}

#[test]
fn test_build_tls_acceptor_success() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let result = build_with(vec!["h2".to_string()], None);
    assert!(result.is_ok(), "should succeed with valid TLS options");
    Ok(())
}

#[test]
fn test_build_tls_acceptor_empty_alpn() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let result = build_with(vec![], None);
    assert!(result.is_ok(), "should succeed with empty ALPN");
    Ok(())
}

#[test]
fn test_build_tls_acceptor_custom_alpn() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let result = build_with(vec!["h2".to_string()], None);
    assert!(result.is_ok(), "should succeed with custom ALPN");
    Ok(())
}

#[test]
fn test_mtls_missing_client_ca() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let result =
        build_with(vec![], Some(ClientAuth { ca_cert_path: "/nonexistent/ca.pem".to_string() }));
    assert!(result.is_err());
    if let Err(err) = result {
        let msg = format!("{err}");
        assert!(msg.contains("Failed to read client CA certificate"));
    }
    Ok(())
}

#[test]
fn test_mtls_invalid_client_ca_pem() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ca_path = tmp_path("invalid_ca.pem");
    fs::write(&ca_path, b"not a valid PEM file")?;
    let result =
        build_with(vec![], Some(ClientAuth { ca_cert_path: ca_path.display().to_string() }));
    let _ = fs::remove_file(&ca_path);
    assert!(result.is_err());
    if let Err(err) = result {
        let msg = format!("{err}");
        assert!(
            msg.contains("Failed to parse client CA certificates")
                || msg.contains("Failed to add CA certificate")
                || msg.contains("Failed to build client verifier")
        );
    }
    Ok(())
}

#[test]
fn test_mtls_valid_client_ca_format() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ca_path = tmp_path("ca.pem");
    let ca_cert = rcgen::generate_simple_self_signed(vec!["ca.example.com".to_string()])?;
    fs::write(&ca_path, ca_cert.cert.pem())?;
    let result =
        build_with(vec![], Some(ClientAuth { ca_cert_path: ca_path.display().to_string() }));
    let _ = fs::remove_file(&ca_path);
    assert!(result.is_ok(), "should succeed with valid CA format");
    Ok(())
}

#[test]
fn test_mtls_multiple_ca_certificates() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ca_path = tmp_path("multi_ca.pem");
    let ca1 = rcgen::generate_simple_self_signed(vec!["ca1.example.com".to_string()])?;
    let ca2 = rcgen::generate_simple_self_signed(vec!["ca2.example.com".to_string()])?;
    let ca3 = rcgen::generate_simple_self_signed(vec!["ca3.example.com".to_string()])?;
    let mut ca_pem = ca1.cert.pem();
    ca_pem.push_str(&ca2.cert.pem());
    ca_pem.push_str(&ca3.cert.pem());
    fs::write(&ca_path, ca_pem)?;
    let result =
        build_with(vec![], Some(ClientAuth { ca_cert_path: ca_path.display().to_string() }));
    let _ = fs::remove_file(&ca_path);
    assert!(result.is_ok(), "should succeed with multiple CA certificates");
    Ok(())
}
