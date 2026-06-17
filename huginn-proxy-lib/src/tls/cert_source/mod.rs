//! TLS server certificate material loaded from disk.
//!
//! Certificates are read from PEM files into [`ServerCertsKeys`] and handed to
//! [`DynamicCertResolver`](crate::tls::cert_resolver::DynamicCertResolver), which
//! owns SNI-based selection and atomic hot-reload. There is no standalone cert
//! source or file watcher: rotation is driven by the config hot-reload path.

use std::hash::{Hash, Hasher};
use std::path::Path;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::fs;
use tracing::debug;

use crate::error::ProxyError;

#[derive(Debug, PartialEq, Eq)]
pub struct ServerCertsKeys {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl Clone for ServerCertsKeys {
    fn clone(&self) -> Self {
        Self { certs: self.certs.to_vec(), key: self.key.clone_key() }
    }
}

/// FNV-1a-style hash of the entire certificate chain (DER bytes, in order).
pub fn cert_chain_hash(certs: &[CertificateDer<'static>]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    for cert in certs {
        cert.as_ref().hash(&mut hasher);
    }
    hasher.finish()
}

/// Read the certificate and private key from the disk.
///
/// Used by [`DynamicCertResolver`](crate::tls::cert_resolver::DynamicCertResolver)
/// to load each domain's cert material during startup and hot-reload.
pub(crate) async fn read_certs_and_keys(
    cert_path: &Path,
    key_path: &Path,
) -> Result<ServerCertsKeys, ProxyError> {
    debug!("Reading TLS server certificates and private key");

    let cert_bytes = fs::read(cert_path).await.map_err(|e| {
        ProxyError::Tls(format!("Unable to load the certificates [{}]: {e}", cert_path.display()))
    })?;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| ProxyError::Tls(format!("Unable to parse the certificates: {e}")))?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();

    if certs.is_empty() {
        return Err(ProxyError::Tls("No certificates found".to_string()));
    }

    let key_bytes = fs::read(key_path).await.map_err(|e| {
        ProxyError::Tls(format!(
            "Unable to load the certificate keys [{}]: {e}",
            key_path.display()
        ))
    })?;

    let mut keys: Vec<PrivateKeyDer<'static>> = PrivateKeyDer::pem_slice_iter(&key_bytes)
        .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| ProxyError::Tls(format!("Unable to parse the private keys: {e}")))?
        .into_iter()
        .map(|k| k.clone_key())
        .collect();

    let key = keys.pop().ok_or_else(|| {
        ProxyError::Tls(
            "No private keys found - Make sure they are in PKCS#8/PEM format".to_string(),
        )
    })?;

    Ok(ServerCertsKeys { certs, key })
}
