//! Cert/key material read from disk.
//!
//! [`ServerCertsKeys`] holds the parsed certificate chain and private key for a
//! single domain, handed to
//! [`DynamicCertResolver`](crate::server_crypto::DynamicCertResolver) which owns
//! SNI-based selection and atomic hot-reload.

use std::hash::{Hash, Hasher};

use rustls_pki_types::{CertificateDer, PrivateKeyDer};

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
