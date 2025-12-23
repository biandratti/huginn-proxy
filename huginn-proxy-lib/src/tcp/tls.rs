#![forbid(unsafe_code)]

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

pub enum ClientStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
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
    let f = File::open(path).map_err(|e| format!("failed to open cert file: {e}"))?;
    let mut reader = BufReader::new(f);
    let certs = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to read certs: {e}"))?;
    if certs.is_empty() {
        return Err("no certificates found".into());
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let f = File::open(path).map_err(|e| format!("failed to open key file: {e}"))?;
    let mut reader = BufReader::new(f);

    let mut pkcs8 = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to read pkcs8 keys: {e}"))?;
    if let Some(k) = pkcs8.pop() {
        return Ok(PrivateKeyDer::from(k));
    }
    let f = File::open(path).map_err(|e| format!("failed to open key file: {e}"))?;
    let mut reader = BufReader::new(f);
    let mut rsa = rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to read rsa keys: {e}"))?;
    if let Some(k) = rsa.pop() {
        return Ok(PrivateKeyDer::from(k));
    }
    Err("no private keys found (pkcs8 or rsa)".into())
}

