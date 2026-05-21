//! Source of TLS server certificates.
//!
//! Two variants:
//! - [`StaticCertSource`]: loaded once at startup, never changes.
//! - [`WatchedCertSource`]: filesystem watcher publishes updates on cert/key

use std::path::Path;
use std::sync::Arc;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::fs;
use tokio::sync::watch;
use tracing::debug;

use crate::error::ProxyError;

pub use static_source::StaticCertSource;
pub use watched_source::WatchedCertSource;

mod static_source;
mod watched_source;

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

/// Source of TLS server certificates.
///
/// Closed enum: the two reasonable shapes today are "loaded once" and
/// "watch the filesystem". Future sources (Vault, K8s secrets, SPIRE…)
/// should be added as new variants, so the exhaustive match in
/// `setup_tls_with_hot_reload` forces every site to handle them.
pub enum CertSource {
    Static(StaticCertSource),
    Watched(WatchedCertSource),
}

impl CertSource {
    /// Snapshot of the currently active certs.
    pub fn current(&self) -> Arc<ServerCertsKeys> {
        match self {
            CertSource::Static(s) => s.current(),
            CertSource::Watched(w) => w.current(),
        }
    }

    /// Subscribe to cert updates.
    ///
    /// Returns `None` for static sources the caller MUST NOT spawn a
    /// reload task. Returns `Some(receiver)` for watched sources, with
    /// each successful reload publishing a new `Arc<ServerCertsKeys>`.
    pub fn subscribe(&self) -> Option<watch::Receiver<Arc<ServerCertsKeys>>> {
        match self {
            CertSource::Static(_) => None,
            CertSource::Watched(w) => Some(w.subscribe()),
        }
    }
}

/// Read the certificate and private key from the disk.
///
/// Used by both `StaticCertSource::load` and the `WatchedCertSource` reload task.
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
