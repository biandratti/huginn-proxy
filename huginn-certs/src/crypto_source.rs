//! Certificate source: loading cert/key material from PEM files.
//!
//! Currently the only source is the filesystem ([`read_certs_and_keys`]). The
//! `CertEntry` description consumed by
//! [`DynamicCertResolver`](crate::server_crypto::DynamicCertResolver) is added
//! alongside the resolver.

use std::path::Path;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::fs;
use tracing::debug;

use crate::certs::ServerCertsKeys;
use crate::error::CertError;

/// Read the certificate and private key from the disk.
///
/// Used by [`DynamicCertResolver`](crate::server_crypto::DynamicCertResolver) to
/// load each domain's cert material during startup and hot-reload.
pub async fn read_certs_and_keys(
    cert_path: &Path,
    key_path: &Path,
) -> Result<ServerCertsKeys, CertError> {
    debug!("Reading TLS server certificates and private key");

    let cert_bytes = fs::read(cert_path).await.map_err(|e| {
        CertError::Tls(format!("Unable to load the certificates [{}]: {e}", cert_path.display()))
    })?;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| CertError::Tls(format!("Unable to parse the certificates: {e}")))?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();

    if certs.is_empty() {
        return Err(CertError::Tls("No certificates found".to_string()));
    }

    let key_bytes = fs::read(key_path).await.map_err(|e| {
        CertError::Tls(format!("Unable to load the certificate keys [{}]: {e}", key_path.display()))
    })?;

    let mut keys: Vec<PrivateKeyDer<'static>> = PrivateKeyDer::pem_slice_iter(&key_bytes)
        .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| CertError::Tls(format!("Unable to parse the private keys: {e}")))?
        .into_iter()
        .map(|k| k.clone_key())
        .collect();

    let key = keys.pop().ok_or_else(|| {
        CertError::Tls(
            "No private keys found - Make sure they are in PKCS#8/PEM format".to_string(),
        )
    })?;

    Ok(ServerCertsKeys { certs, key })
}
