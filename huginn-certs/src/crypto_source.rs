//! Certificate source: where a domain's cert/key material comes from.
//!
//! [`CryptoSource`] abstracts *the origin* of the material so the resolver does
//! not care whether it is a file, a secret store, or an in-memory blob. The only
//! implementation today is [`CryptoFileSource`] (backed by [`read_certs_and_keys`]),
//! but the trait keeps the door open to other sources without touching the
//! per-SNI config builder. A [`CertEntry`] pairs one such source with its SNI host
//! and label for [`build_server_crypto`](crate::build::build_server_crypto).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::fs;
use tracing::{debug, warn};

use crate::certs::ServerCertsKeys;
use crate::error::CertError;

/// Where a domain's certificate and private key are read from.
///
/// Abstracting the origin lets the resolver load material uniformly regardless
/// of backend (filesystem today; a secret store, KMS, or in-memory blob could be
/// added without changing the resolver). Implementations must be cheap to clone
/// or shared behind an `Arc`, since [`CertEntry`] holds them as `Arc<dyn CryptoSource>`.
#[async_trait]
pub trait CryptoSource: std::fmt::Debug + Send + Sync {
    /// Read the certificate chain and private key for one domain.
    async fn read(&self) -> Result<ServerCertsKeys, CertError>;
}

/// A [`CryptoSource`] backed by PEM files on disk.
///
/// Reads the server certificate chain and private key, plus an optional client-CA
/// bundle that turns on mutual TLS for the domain.
#[derive(Debug, Clone)]
pub struct CryptoFileSource {
    /// Path to the certificate chain PEM file.
    pub cert_path: PathBuf,
    /// Path to the private key PEM file.
    pub key_path: PathBuf,
    /// Optional path to a client-CA bundle PEM file. When set, the domain
    /// requires mutual TLS and client certs are verified against these CAs.
    pub client_ca_path: Option<PathBuf>,
}

impl CryptoFileSource {
    /// Build a file source from a cert and key path (no client auth).
    pub fn new(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        Self { cert_path: cert_path.into(), key_path: key_path.into(), client_ca_path: None }
    }

    /// Enable mutual TLS for this source by pointing at a client-CA bundle.
    #[must_use]
    pub fn with_client_ca(mut self, client_ca_path: impl Into<PathBuf>) -> Self {
        self.client_ca_path = Some(client_ca_path.into());
        self
    }
}

#[async_trait]
impl CryptoSource for CryptoFileSource {
    async fn read(&self) -> Result<ServerCertsKeys, CertError> {
        read_certs_and_keys(&self.cert_path, &self.key_path, self.client_ca_path.as_deref()).await
    }
}

/// One domain's certificate material, decoupled from the proxy's config types.
///
/// The caller (huginn-proxy-lib) translates each configured domain that declares
/// a cert into a `CertEntry`; domains without a cert source are filtered out
/// before reaching the resolver.
#[derive(Debug, Clone)]
pub struct CertEntry {
    /// SNI host this cert serves. `None` = catch-all (populates the default cert
    /// slot). `Some("*.base")` = wildcard; `Some("host")` = exact match.
    pub host: Option<String>,
    /// Where the cert/key material is read from (filesystem, etc.).
    pub source: Arc<dyn CryptoSource>,
    /// Stable identifier for metrics/logs (the host, or `"_default_"` for the
    /// catch-all). Chosen by the caller so the crate stays config-agnostic.
    pub label: String,
}

/// Read the certificate, private key, and optional client-CA bundle from disk.
///
/// Used by [`build_server_crypto`](crate::build::build_server_crypto) to load each
/// domain's cert material during startup and hot-reload. When `client_ca_path` is
/// `Some`, the returned material carries the parsed client-CA trust anchors and
/// [`ServerCertsKeys::is_mutual_tls`] reports `true`.
pub async fn read_certs_and_keys(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
) -> Result<ServerCertsKeys, CertError> {
    debug!("Reading TLS server certificates and private key");

    let cert_bytes = fs::read(cert_path).await.map_err(|source| CertError::Io {
        kind: "certificates",
        path: cert_path.display().to_string(),
        source,
    })?;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| CertError::Parse(format!("certificates: {e}")))?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();

    if certs.is_empty() {
        return Err(CertError::NoCertificates);
    }

    warn_if_key_perm_loose(key_path);

    let key_bytes = fs::read(key_path).await.map_err(|source| CertError::Io {
        kind: "certificate keys",
        path: key_path.display().to_string(),
        source,
    })?;

    let mut keys: Vec<PrivateKeyDer<'static>> = PrivateKeyDer::pem_slice_iter(&key_bytes)
        .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| CertError::Parse(format!("private keys: {e}")))?
        .into_iter()
        .map(|k| k.clone_key())
        .collect();

    let key = keys.pop().ok_or(CertError::NoPrivateKey)?;

    let client_ca_certs = match client_ca_path {
        Some(path) => Some(read_client_ca_certs(path).await?),
        None => None,
    };

    Ok(ServerCertsKeys { certs, key, client_ca_certs })
}

/// Read and parse a client-CA bundle PEM file into trust anchors for mTLS.
///
/// Errors with [`CertError::NoClientCert`] if the file parses but is empty, so a
/// misconfigured mTLS domain fails loudly instead of silently disabling client
/// auth.
async fn read_client_ca_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, CertError> {
    let ca_bytes = fs::read(path).await.map_err(|source| CertError::Io {
        kind: "client CA certificates",
        path: path.display().to_string(),
        source,
    })?;

    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&ca_bytes)
        .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| CertError::Parse(format!("client CA certificates: {e}")))?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();

    if ca_certs.is_empty() {
        return Err(CertError::NoClientCert);
    }

    Ok(ca_certs)
}

/// Emit a `warn!` if the private key file at `path` has any group- or
/// other-readable permission bits set. Unix-only observability helper: it does
/// not modify the file and does not gate loading. A metadata error is silently
/// ignored, since the subsequent read will surface the real error.
fn warn_if_key_perm_loose(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 == 0 {
            return;
        }
        if mode & 0o004 != 0 {
            warn!(
                mode = format!("{mode:o}"),
                path = %path.display(),
                "TLS private key file is world-readable; recommended mode is 0600"
            );
        } else {
            warn!(
                mode = format!("{mode:o}"),
                path = %path.display(),
                "TLS private key file has loose permissions; recommended mode is 0600"
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
