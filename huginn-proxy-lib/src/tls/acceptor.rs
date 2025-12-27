use std::sync::Arc;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;
use crate::error::{ProxyError, Result};

pub async fn read_client_hello(
    stream: &mut tokio::net::TcpStream,
) -> std::io::Result<(Vec<u8>, Option<String>)> {
    use huginn_net_tls::tls_process::parse_tls_client_hello_ja4;
    use tokio::io::AsyncReadExt;

    let mut buf = Vec::with_capacity(8192);
    loop {
        if buf.len() >= 5 {
            let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let needed = len.saturating_add(5);
            if buf.len() >= needed {
                break;
            }
        }
        let read = stream.read_buf(&mut buf).await?;
        if read == 0 {
            break;
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }

    let ja4 = parse_tls_client_hello_ja4(&buf);

    Ok((buf, ja4))
}

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

    let mut server = RustlsServerConfig::builder()
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
