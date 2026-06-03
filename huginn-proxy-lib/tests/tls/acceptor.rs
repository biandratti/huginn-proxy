use crate::helpers::{create_dummy_test_cert, create_valid_test_cert, tmp_path};
use huginn_proxy_lib::config::ClientAuth;
use huginn_proxy_lib::tls::build_server_config;
use huginn_proxy_lib::tls::cert_source::{CertSource, StaticCertSource};
use std::fs;

async fn build_from_files(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    alpn: Vec<String>,
    client_auth: ClientAuth,
) -> huginn_proxy_lib::error::Result<()> {
    let source = CertSource::Static(StaticCertSource::load(cert_path, key_path).await?);
    let certs = source.current();
    build_server_config(
        certs.certs.clone(),
        certs.key.clone_key(),
        &alpn,
        &Default::default(),
        &client_auth,
        &Default::default(),
    )?;
    Ok(())
}

#[tokio::test]
async fn test_build_tls_acceptor_success() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let result =
        build_from_files(&cert_path, &key_path, vec!["h2".to_string()], ClientAuth::Disabled).await;
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    assert!(result.is_ok(), "should succeed with valid certificates");
    Ok(())
}

#[tokio::test]
async fn test_build_tls_acceptor_missing_cert(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let result = build_from_files(
        std::path::Path::new("/nonexistent/cert.pem"),
        std::path::Path::new("/nonexistent/key.pem"),
        vec![],
        ClientAuth::Disabled,
    )
    .await;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn test_build_tls_acceptor_empty_alpn() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let (cert_path, key_path) = create_valid_test_cert()?;
    let result = build_from_files(&cert_path, &key_path, vec![], ClientAuth::Disabled).await;
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    assert!(result.is_ok(), "should succeed with empty ALPN");
    Ok(())
}

#[tokio::test]
async fn test_build_tls_acceptor_custom_alpn(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let result =
        build_from_files(&cert_path, &key_path, vec!["h2".to_string()], ClientAuth::Disabled).await;
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    assert!(result.is_ok(), "should succeed with custom ALPN");
    Ok(())
}

#[tokio::test]
async fn test_build_tls_acceptor_invalid_pem(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = tmp_path("invalid.crt");
    let key_path = tmp_path("invalid.key");
    fs::write(&cert_path, b"not a valid PEM file")?;
    fs::write(&key_path, b"not a valid PEM file")?;
    let result = build_from_files(&cert_path, &key_path, vec![], ClientAuth::Disabled).await;
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn test_mtls_missing_client_ca() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_dummy_test_cert()?;
    let result = build_from_files(
        &cert_path,
        &key_path,
        vec![],
        ClientAuth::Required { ca_cert_path: "/nonexistent/ca.pem".to_string() },
    )
    .await;
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    assert!(result.is_err());
    if let Err(err) = result {
        let msg = format!("{err}");
        assert!(msg.contains("Failed to read client CA certificate"));
    }
    Ok(())
}

#[tokio::test]
async fn test_mtls_invalid_client_ca_pem() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_dummy_test_cert()?;
    let ca_path = tmp_path("invalid_ca.pem");
    fs::write(&ca_path, b"not a valid PEM file")?;
    let result = build_from_files(
        &cert_path,
        &key_path,
        vec![],
        ClientAuth::Required { ca_cert_path: ca_path.display().to_string() },
    )
    .await;
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
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

#[tokio::test]
async fn test_mtls_valid_client_ca_format() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let (cert_path, key_path) = create_valid_test_cert()?;
    let ca_path = tmp_path("ca.pem");
    let ca_cert = rcgen::generate_simple_self_signed(vec!["ca.example.com".to_string()])?;
    fs::write(&ca_path, ca_cert.cert.pem())?;
    let result = build_from_files(
        &cert_path,
        &key_path,
        vec![],
        ClientAuth::Required { ca_cert_path: ca_path.display().to_string() },
    )
    .await;
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&ca_path);
    assert!(result.is_ok(), "should succeed with valid CA format");
    Ok(())
}

#[tokio::test]
async fn test_mtls_multiple_ca_certificates() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let (cert_path, key_path) = create_valid_test_cert()?;
    let ca_path = tmp_path("multi_ca.pem");
    let ca1 = rcgen::generate_simple_self_signed(vec!["ca1.example.com".to_string()])?;
    let ca2 = rcgen::generate_simple_self_signed(vec!["ca2.example.com".to_string()])?;
    let ca3 = rcgen::generate_simple_self_signed(vec!["ca3.example.com".to_string()])?;
    let mut ca_pem = ca1.cert.pem();
    ca_pem.push_str(&ca2.cert.pem());
    ca_pem.push_str(&ca3.cert.pem());
    fs::write(&ca_path, ca_pem)?;
    let result = build_from_files(
        &cert_path,
        &key_path,
        vec![],
        ClientAuth::Required { ca_cert_path: ca_path.display().to_string() },
    )
    .await;
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&ca_path);
    assert!(result.is_ok(), "should succeed with multiple CA certificates");
    Ok(())
}

#[test]
fn test_client_auth_enum_default() {
    let default_auth = ClientAuth::default();
    assert!(matches!(default_auth, ClientAuth::Disabled));
}
