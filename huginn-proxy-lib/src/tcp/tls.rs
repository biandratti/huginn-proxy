#![forbid(unsafe_code)]

use std::sync::Arc;

use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::net::TcpStream;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

pub type TlsSignature = Option<String>;

pub enum ClientStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>, TlsSignature),
}

pub fn build_tls_acceptor(
    cert_path: &str,
    key_path: &str,
    alpn: &[String],
) -> Result<Arc<TlsAcceptor>, String> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("failed to build tls config: {e}"))?;

    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    }

    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    Ok(Arc::new(acceptor))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let buf = std::fs::read(path).map_err(|e| format!("failed to open cert file: {e}"))?;
    let cert =
        CertificateDer::from_pem_slice(&buf).map_err(|e| format!("failed to parse cert: {e}"))?;
    Ok(vec![cert])
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let buf = std::fs::read(path).map_err(|e| format!("failed to open key file: {e}"))?;
    PrivateKeyDer::from_pem_slice(&buf).map_err(|e| format!("failed to parse key: {e}"))
}
