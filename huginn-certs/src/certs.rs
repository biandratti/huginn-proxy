//! Cert/key material read from disk.
//!
//! [`ServerCertsKeys`] holds the parsed certificate chain and private key for a
//! single domain, handed to
//! [`DynamicCertResolver`](crate::server_crypto::DynamicCertResolver) which owns
//! SNI-based selection and atomic hot-reload.

use std::hash::{Hash, Hasher};

use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// A parsed certificate chain and its matching private key for one domain.
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
