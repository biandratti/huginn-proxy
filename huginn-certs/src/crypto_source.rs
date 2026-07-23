//! Certificate source: loading cert/key material from PEM files.
//!
//! Currently the only source is the filesystem ([`read_certs_and_keys`]). A
//! [`CertEntry`] describes one domain's cert material for
//! [`DynamicCertResolver::update`](crate::server_crypto::DynamicCertResolver::update).

use std::path::{Path, PathBuf};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::fs;
use tracing::{debug, warn};

use crate::certs::ServerCertsKeys;
use crate::error::CertError;

/// One domain's certificate material, decoupled from the proxy's config types.
///
/// The caller (huginn-proxy-lib) translates each configured domain that declares
/// a cert into a `CertEntry`; domains without cert/key paths are filtered out
/// before reaching the resolver.
#[derive(Debug, Clone)]
pub struct CertEntry {
    /// SNI host this cert serves. `None` = catch-all (populates the default cert
    /// slot). `Some("*.base")` = wildcard; `Some("host")` = exact match.
    pub host: Option<String>,
    /// Path to the certificate chain PEM file.
    pub cert_path: PathBuf,
    /// Path to the private key PEM file.
    pub key_path: PathBuf,
    /// Stable identifier for metrics/logs (the host, or `"_default_"` for the
    /// catch-all). Chosen by the caller so the crate stays config-agnostic.
    pub label: String,
}

/// Read the certificate and private key from the disk.
///
/// Used by [`DynamicCertResolver`](crate::server_crypto::DynamicCertResolver) to
/// load each domain's cert material during startup and hot-reload.
pub async fn read_certs_and_keys(
    cert_path: &Path,
    key_path: &Path,
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

    Ok(ServerCertsKeys { certs, key })
}

/// TODO: WIP..
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
