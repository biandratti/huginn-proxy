use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Load a certificate chain and private key from PEM files on disk.
pub async fn load_certs_keys_from_pem(
    cert_path: &Path,
    key_path: &Path,
) -> Result<
    (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let cert_bytes = tokio::fs::read(cert_path).await?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();
    if certs.is_empty() {
        return Err("No certificates found".into());
    }

    let key_bytes = tokio::fs::read(key_path).await?;
    let mut keys: Vec<PrivateKeyDer<'static>> = PrivateKeyDer::pem_slice_iter(&key_bytes)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|k| k.clone_key())
        .collect();
    let key = keys.pop().ok_or("No private keys found")?;

    Ok((certs, key))
}

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
    ensure_crypto_provider();
    let cert_path = tmp_path("test.crt");
    let key_path = tmp_path("test.key");

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
    ensure_crypto_provider();
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

/// Generate dummy (invalid) test certificates as DER (for direct use with rustls)
///
/// The bytes are syntactically arbitrary rustls will reject them.
/// Use for tests that exercise the error path of `build_tls_acceptor` or
/// similar functions without needing cryptographically valid material.
pub fn generate_dummy_test_cert_der() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    ensure_crypto_provider();
    let cert = CertificateDer::from(b"dummy cert".to_vec());
    let key =
        PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(b"dummy key".to_vec()));
    (cert, key)
}

/// Generate valid test certificates as DER (for direct use with rustls)
/// Returns CertificateDer and PrivateKeyDer for direct use in ServerConfig
pub fn generate_valid_test_cert_der() -> Result<
    (CertificateDer<'static>, PrivateKeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    ensure_crypto_provider();
    let subject_alt_names = vec!["localhost".to_string()];
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(subject_alt_names)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
        signing_key.serialize_der(),
    ));

    Ok((cert_der, key_der))
}

/// Ensure the rustls process-level `CryptoProvider` is installed exactly once.
pub fn ensure_crypto_provider() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
