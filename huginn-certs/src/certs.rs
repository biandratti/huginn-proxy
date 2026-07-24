//! Cert/key material read from disk.
//!
//! [`ServerCertsKeys`] holds the parsed certificate chain and private key for a
//! single domain, handed to
//! [`build_server_crypto`](crate::server_crypto::build_server_crypto) which turns it into a
//! per-SNI rustls `ServerConfig`.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::sign::CertifiedKey;
use tracing::warn;

use crate::error::CertError;

/// A parsed certificate chain and its matching private key for one domain.
///
/// Optionally carries the client-CA trust anchors for that domain: when present
/// the domain requires mutual TLS, verifying client certificates against them.
/// Because rustls binds the client-cert verifier to the `ServerConfig` (not to
/// the resolved cert), keeping the client CA here lets mTLS be configured
/// per-domain and hot-reloaded alongside the server cert.
#[derive(Debug, PartialEq, Eq)]
pub struct ServerCertsKeys {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    /// Client-CA trust anchors for mutual TLS. `None` (or empty) = this domain
    /// does not require client certificates.
    pub client_ca_certs: Option<Vec<CertificateDer<'static>>>,
}

impl ServerCertsKeys {
    /// Whether this domain enables mutual TLS, i.e. it carries client-CA trust
    /// anchors to verify client certificates against.
    pub fn is_mutual_tls(&self) -> bool {
        self.client_ca_certs
            .as_ref()
            .is_some_and(|ca| !ca.is_empty())
    }
}

impl Clone for ServerCertsKeys {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.to_vec(),
            key: self.key.clone_key(),
            client_ca_certs: self.client_ca_certs.clone(),
        }
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

/// Build a rustls [`CertifiedKey`] from parsed material, returning it with the
/// chain hash.
///
/// Shared by the SNI resolver and the per-SNI `ServerConfig` builder. `label`
/// only tags errors. A key that cannot be *proven* to match the cert
/// (`InconsistentKeys::Unknown`, e.g. some PSS/EC combinations) is accepted with
/// a warning, matching rustls' own leniency; a proven mismatch is rejected.
pub(crate) fn build_certified_key(
    material: &ServerCertsKeys,
    label: &str,
) -> Result<(Arc<CertifiedKey>, u64), CertError> {
    let signing_key = tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(
        &material.key,
    )
    .map_err(|e| CertError::SigningKey { label: label.to_string(), message: e.to_string() })?;
    let cert_hash = cert_chain_hash(&material.certs);
    let certified_key = Arc::new(CertifiedKey::new(material.certs.clone(), signing_key));

    match certified_key.keys_match() {
        Ok(()) => {}
        Err(tokio_rustls::rustls::Error::InconsistentKeys(
            tokio_rustls::rustls::InconsistentKeys::Unknown,
        )) => {
            warn!(
                host = label,
                "could not verify that the private key matches the certificate; proceeding"
            );
        }
        Err(e) => {
            return Err(CertError::KeyMismatch {
                label: label.to_string(),
                message: e.to_string(),
            });
        }
    }

    Ok((certified_key, cert_hash))
}
