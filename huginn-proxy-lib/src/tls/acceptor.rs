use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;
use crate::error::{ProxyError, Result};

/// Builds a TLS acceptor from configuration
pub fn build_rustls(cfg: &TlsConfig) -> Result<TlsAcceptor> {
    let certs = {
        let bytes = std::fs::read(&cfg.cert_path)
            .map_err(|e| ProxyError::Tls(format!("Failed to read certificate: {e}")))?;
        CertificateDer::pem_slice_iter(&bytes)
            .collect::<std::result::Result<Vec<_>, rustls_pki_types::pem::Error>>()
            .map_err(|e| ProxyError::Tls(format!("Failed to parse certificates: {e}")))?
    };

    let key = {
        let bytes = std::fs::read(&cfg.key_path)
            .map_err(|e| ProxyError::Tls(format!("Failed to read key: {e}")))?;
        let mut keys: Vec<PrivateKeyDer<'_>> = PrivateKeyDer::pem_slice_iter(&bytes)
            .collect::<std::result::Result<Vec<_>, rustls_pki_types::pem::Error>>()
            .map_err(|e| ProxyError::Tls(format!("Failed to parse private key: {e}")))?;
        let Some(k) = keys.pop() else {
            return Err(ProxyError::NoPrivateKey);
        };
        k
    };

    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ProxyError::Tls(format!("Failed to build TLS config: {e}")))?;

    if !cfg.alpn.is_empty() {
        server.alpn_protocols = cfg.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    } else {
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }

    Ok(TlsAcceptor::from(Arc::new(server)))
}
