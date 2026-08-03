//! Cert/key material read from disk.
//!
//! [`ServerCertsKeys`] holds the parsed certificate chain and private key for a
//! single domain, handed to
//! [`build_server_crypto`](crate::server_crypto::build_server_crypto) which turns it into a
//! per-SNI rustls `ServerConfig`.

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
    /// Every private key the source yielded, in the order it produced them.
    /// Which one goes with `certs` is decided when the config is built, since only
    /// a comparison against the chain can tell them apart.
    pub keys: Vec<PrivateKeyDer<'static>>,
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
            keys: self.keys.iter().map(|k| k.clone_key()).collect(),
            client_ca_certs: self.client_ca_certs.clone(),
        }
    }
}

/// The two FNV-1a 64-bit parameters, fixed by the spec.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a (64-bit) over `bytes`.
///
/// These hashes are exported as metrics, so the algorithm has to be a frozen spec:
/// `std`'s `DefaultHasher` is not, and a toolchain upgrade could move a value that
/// is supposed to change only when the content does. Not collision-resistant.
pub fn fnv1a_hash(bytes: &[u8]) -> u64 {
    fnv1a_fold(FNV_OFFSET_BASIS, bytes)
}

/// Fold `bytes` into an in-progress hash, so one value can span several slices.
fn fnv1a_fold(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// FNV-1a hash of the whole certificate chain (DER bytes, in order).
///
/// One running hash over the concatenation: DER is self-delimiting, so no separator
/// between certs is needed.
pub fn cert_chain_hash(certs: &[CertificateDer<'static>]) -> u64 {
    certs
        .iter()
        .fold(FNV_OFFSET_BASIS, |hash, cert| fnv1a_fold(hash, cert.as_ref()))
}

/// Build a rustls [`CertifiedKey`] from parsed material, returning it with the
/// chain hash.
///
/// Shared by the SNI resolver and the per-SNI `ServerConfig` builder. `label`
/// only tags errors.
///
/// A key file may hold more than one key, so the candidates are tried in order and
/// the first one that provably matches the chain wins. A key that cannot be
/// *proven* to match (`InconsistentKeys::Unknown`, e.g. some PSS/EC combinations)
/// is only used when no other key proves itself, and then with a warning, matching
/// rustls' own leniency. Keys the provider rejects, and keys that provably belong
/// to a different certificate, are skipped; if that leaves nothing, the proven
/// mismatch is the more actionable error to report.
pub(crate) fn build_certified_key(
    material: &ServerCertsKeys,
    label: &str,
) -> Result<(Arc<CertifiedKey>, u64), CertError> {
    if material.keys.is_empty() {
        return Err(CertError::NoPrivateKey);
    }
    let cert_hash = cert_chain_hash(&material.certs);

    let mut unproven: Option<Arc<CertifiedKey>> = None;
    let mut mismatch: Option<String> = None;
    let mut unsupported: Option<String> = None;

    for key in &material.keys {
        let signing_key =
            match tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(key) {
                Ok(signing_key) => signing_key,
                Err(e) => {
                    unsupported.get_or_insert_with(|| e.to_string());
                    continue;
                }
            };
        let certified_key = Arc::new(CertifiedKey::new(material.certs.clone(), signing_key));

        match certified_key.keys_match() {
            Ok(()) => return Ok((certified_key, cert_hash)),
            Err(tokio_rustls::rustls::Error::InconsistentKeys(
                tokio_rustls::rustls::InconsistentKeys::Unknown,
            )) => {
                if unproven.is_none() {
                    unproven = Some(certified_key);
                }
            }
            Err(e) => {
                mismatch.get_or_insert_with(|| e.to_string());
            }
        }
    }

    if let Some(certified_key) = unproven {
        warn!(
            host = label,
            "could not verify that the private key matches the certificate; proceeding"
        );
        return Ok((certified_key, cert_hash));
    }
    if let Some(message) = mismatch {
        return Err(CertError::KeyMismatch { label: label.to_string(), message });
    }
    Err(CertError::SigningKey {
        label: label.to_string(),
        message: unsupported.unwrap_or_else(|| "no usable private key".to_string()),
    })
}
