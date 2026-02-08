//! Shared test helpers for TLS tests

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Generate a temporary file path for testing
pub fn tmp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    std::env::temp_dir().join(format!("huginn-test-{nanos}-{name}"))
}

/// Create dummy (invalid) test certificates in PEM format
/// These are valid PEM format but not cryptographically valid certificates
/// Use for tests that expect certificate parsing/validation errors
pub fn create_dummy_test_cert(
) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error + Send + Sync>> {
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

/// Generate valid test certificates using rcgen
/// Returns paths to PEM files containing valid self-signed certificates
/// Use for tests that need cryptographically valid certificates
pub fn create_valid_test_cert(
) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = tmp_path("test.crt");
    let key_path = tmp_path("test.key");

    let subject_alt_names = vec!["localhost".to_string()];
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(subject_alt_names)?;

    // Write certificate in PEM format
    fs::write(&cert_path, cert.pem())?;

    // Write private key in PEM format
    fs::write(&key_path, signing_key.serialize_pem())?;

    Ok((cert_path, key_path))
}

/// Generate valid test certificates as DER (for direct use with rustls)
/// Returns CertificateDer and PrivateKeyDer for direct use in ServerConfig
pub fn generate_valid_test_cert_der() -> Result<
    (
        rustls_pki_types::CertificateDer<'static>,
        rustls_pki_types::PrivateKeyDer<'static>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let subject_alt_names = vec!["localhost".to_string()];
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(subject_alt_names)?;

    let cert_der = rustls_pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
        rustls_pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
    );

    Ok((cert_der, key_der))
}
