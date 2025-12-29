use crate::config::TlsConfig;
use crate::error::ProxyError;
use async_trait::async_trait;
use hot_reload::{Reload, ReloaderError};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio_rustls::rustls::{pki_types::pem::PemObject, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, warn};

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

impl ServerCertsKeys {
    pub fn build_tls_acceptor(&self, alpn: &[String]) -> crate::error::Result<TlsAcceptor> {
        let mut server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.certs.to_vec(), self.key.clone_key())
            .map_err(|e| ProxyError::Tls(format!("Failed to build TLS config: {e}")))?;

        if !alpn.is_empty() {
            server.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        } else {
            server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }

        Ok(TlsAcceptor::from(Arc::new(server)))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerCryptoBase {
    /// Map of server name (currently unused, single server) to certs and keys
    pub(super) inner: HashMap<String, ServerCertsKeys>,
}

impl ServerCryptoBase {
    /// Get the TlsAcceptor for the first (and only) server
    pub fn get_tls_acceptor(&self, alpn: &[String]) -> crate::error::Result<TlsAcceptor> {
        let (_, certs_keys) = self
            .inner
            .iter()
            .next()
            .ok_or_else(|| ProxyError::Tls("No certificates loaded".to_string()))?;
        certs_keys.build_tls_acceptor(alpn)
    }
}

#[derive(Debug, Clone)]
pub struct CryptoFileSource {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[async_trait]
pub trait CryptoSource {
    type Error;

    async fn read(&self) -> std::result::Result<ServerCertsKeys, Self::Error>;
}

#[async_trait]
impl CryptoSource for CryptoFileSource {
    type Error = ProxyError;

    async fn read(&self) -> std::result::Result<ServerCertsKeys, Self::Error> {
        read_certs_and_keys(&self.cert_path, &self.key_path).await
    }
}

async fn read_certs_and_keys(
    cert_path: &Path,
    key_path: &Path,
) -> Result<ServerCertsKeys, ProxyError> {
    debug!("Reading TLS server certificates and private key");

    let cert_bytes = fs::read(cert_path).await.map_err(|e| {
        ProxyError::Tls(format!("Unable to load the certificates [{}]: {e}", cert_path.display()))
    })?;

    let certs = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<std::result::Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| ProxyError::Tls(format!("Unable to parse the certificates: {e}")))?;

    if certs.is_empty() {
        return Err(ProxyError::Tls("No certificates found".to_string()));
    }

    let key_bytes = fs::read(key_path).await.map_err(|e| {
        ProxyError::Tls(format!(
            "Unable to load the certificate keys [{}]: {e}",
            key_path.display()
        ))
    })?;

    let mut keys: Vec<PrivateKeyDer<'static>> = PrivateKeyDer::pem_slice_iter(&key_bytes)
        .collect::<std::result::Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| ProxyError::Tls(format!("Unable to parse the private keys: {e}")))?;

    let key = keys.pop().ok_or_else(|| {
        ProxyError::Tls(
            "No private keys found - Make sure they are in PKCS#8/PEM format".to_string(),
        )
    })?;

    Ok(ServerCertsKeys { certs: certs.into_iter().collect(), key })
}

#[derive(Clone)]
pub struct CertReloader {
    inner: HashMap<String, Arc<Box<dyn CryptoSource<Error = ProxyError> + Send + Sync>>>,
}

#[async_trait]
impl Reload<ServerCryptoBase> for CertReloader {
    type Source = HashMap<String, Arc<Box<dyn CryptoSource<Error = ProxyError> + Send + Sync>>>;

    async fn new(
        source: &Self::Source,
    ) -> std::result::Result<Self, ReloaderError<ServerCryptoBase>> {
        let mut inner = HashMap::new();
        inner.extend(source.iter().map(|(k, v)| (k.clone(), Arc::clone(v))));
        Ok(Self { inner })
    }

    async fn reload(
        &self,
    ) -> std::result::Result<Option<ServerCryptoBase>, ReloaderError<ServerCryptoBase>> {
        let mut server_crypto_base = ServerCryptoBase::default();

        for (server_name, crypto_source) in self.inner.iter() {
            let certs_keys = match crypto_source.read().await {
                Ok(certs_keys) => certs_keys,
                Err(e) => {
                    error!(
                        "Failed to read certs and keys for {}, skip at this time: {}",
                        server_name, e
                    );
                    continue;
                }
            };
            server_crypto_base
                .inner
                .insert(server_name.clone(), certs_keys);
        }

        if server_crypto_base.inner.is_empty() {
            warn!("No certificates loaded after reload");
            return Ok(None);
        }

        Ok(Some(server_crypto_base))
    }
}

pub async fn build_cert_reloader(
    tls_config: &TlsConfig,
) -> std::result::Result<
    (
        hot_reload::ReloaderService<CertReloader, ServerCryptoBase>,
        hot_reload::ReloaderReceiver<ServerCryptoBase>,
    ),
    ProxyError,
> {
    let mut source_map: HashMap<
        String,
        Arc<Box<dyn CryptoSource<Error = ProxyError> + Send + Sync>>,
    > = HashMap::new();

    let crypto_source = CryptoFileSource {
        cert_path: PathBuf::from(&tls_config.cert_path),
        key_path: PathBuf::from(&tls_config.key_path),
    };

    source_map.insert(
        "default".to_string(),
        Arc::new(Box::new(crypto_source) as Box<dyn CryptoSource<Error = ProxyError> + Send + Sync>),
    );

    let certs_watch_period = tls_config.watch_delay_secs;

    // Initialize ReloaderService (async - sets up filesystem watcher)
    let (cert_reloader_service, cert_reloader_rx) =
        hot_reload::ReloaderService::<CertReloader, ServerCryptoBase>::with_delay(
            &source_map,
            certs_watch_period,
        )
        .await
        .map_err(|e| ProxyError::Tls(format!("Failed to create certificate reloader: {e}")))?;

    Ok((cert_reloader_service, cert_reloader_rx))
}
