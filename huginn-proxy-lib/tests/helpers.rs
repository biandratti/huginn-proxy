use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Generate a temporary file path for testing
pub fn tmp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    std::env::temp_dir().join(format!("huginn-test-{nanos}-{name}"))
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
