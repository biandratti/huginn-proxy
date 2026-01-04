use crate::config::{TlsConfig, TlsOptions};
use crate::error::ProxyError;
use crate::tls::acceptor::validate_tls_options;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::watch;
use tokio::time::{sleep, sleep_until, Duration, Instant};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

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
    pub fn build_tls_acceptor(
        &self,
        alpn: &[String],
        options: &TlsOptions,
    ) -> crate::error::Result<TlsAcceptor> {
        validate_tls_options(options)?;

        let mut server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.certs.to_vec(), self.key.clone_key())
            .map_err(|e| ProxyError::Tls(format!("Failed to build TLS config: {e}")))?;

        if !options.cipher_suites.is_empty() {
            warn!(
                "Cipher suite specification is not yet fully supported in rustls 0.23. \
                Using safe defaults. Specified cipher suites: {:?}",
                options.cipher_suites
            );
        }

        if !alpn.is_empty() {
            server.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        }
        // If alpn is empty, leave server.alpn_protocols as default (empty = no ALPN)

        Ok(TlsAcceptor::from(Arc::new(server)))
    }
}

pub async fn read_certs_and_keys(
    cert_path: &Path,
    key_path: &Path,
) -> Result<ServerCertsKeys, ProxyError> {
    debug!("Reading TLS server certificates and private key");

    let cert_bytes = fs::read(cert_path).await.map_err(|e| {
        ProxyError::Tls(format!("Unable to load the certificates [{}]: {e}", cert_path.display()))
    })?;

    // Parse certificates and convert to 'static lifetime by leaking the bytes (the bytes will live for the lifetime of the program)
    let cert_bytes_leaked: &'static [u8] = Box::leak(cert_bytes.into_boxed_slice());
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_bytes_leaked)
        .collect::<std::result::Result<Vec<CertificateDer<'static>>, rustls_pki_types::pem::Error>>(
        )
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

    // Parse keys and convert to 'static lifetime by leaking the bytes (the bytes will live for the lifetime of the program)
    let key_bytes_leaked: &'static [u8] = Box::leak(key_bytes.into_boxed_slice());
    let mut keys: Vec<PrivateKeyDer<'static>> = PrivateKeyDer::pem_slice_iter(key_bytes_leaked)
        .collect::<std::result::Result<Vec<PrivateKeyDer<'static>>, rustls_pki_types::pem::Error>>()
        .map_err(|e| ProxyError::Tls(format!("Unable to parse the private keys: {e}")))?;

    let key = keys.pop().ok_or_else(|| {
        ProxyError::Tls(
            "No private keys found - Make sure they are in PKCS#8/PEM format".to_string(),
        )
    })?;

    Ok(ServerCertsKeys { certs, key })
}

/// Build certificate reloader with filesystem watching
///
/// Returns a receiver that will receive updates when certificates change.
/// The watcher runs in a background task and monitors the certificate files.
pub async fn build_cert_reloader(
    tls_config: &TlsConfig,
) -> Result<watch::Receiver<Option<ServerCertsKeys>>, ProxyError> {
    let cert_path = PathBuf::from(&tls_config.cert_path);
    let key_path = PathBuf::from(&tls_config.key_path);
    let watch_delay_secs = tls_config.watch_delay_secs;

    // Load initial certificates
    let initial_certs_keys = read_certs_and_keys(&cert_path, &key_path).await?;

    // Create watch channel for certificate updates
    let (tx, rx) = watch::channel(Some(initial_certs_keys));

    // Channel to communicate file change events from watcher to reload task
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    // Setup filesystem watcher
    let cert_path_for_watcher = cert_path.clone();
    let key_path_for_watcher = key_path.clone();
    let mut watcher = RecommendedWatcher::new(
        move |result: Result<notify::Event, notify::Error>| {
            if let Ok(event) = result {
                // Only react to file modifications and creation
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    // Check if the event is for our certificate or key files
                    let is_cert_file = event.paths.iter().any(|p| p == &cert_path_for_watcher);
                    let is_key_file = event.paths.iter().any(|p| p == &key_path_for_watcher);
                    if is_cert_file || is_key_file {
                        // Send event to reload task
                        let _ = event_tx.send(());
                    }
                }
            }
        },
        Config::default(),
    )
    .map_err(|e| ProxyError::Tls(format!("Failed to create filesystem watcher: {e}")))?;

    let parent_dir = cert_path
        .parent()
        .ok_or_else(|| ProxyError::Tls("Certificate path has no parent directory".to_string()))?;
    watcher
        .watch(parent_dir, RecursiveMode::NonRecursive)
        .map_err(|e| ProxyError::Tls(format!("Failed to watch certificate directory: {e}")))?;

    // Spawn background task to handle reloads with debouncing
    let cert_path_for_task = cert_path.clone();
    let key_path_for_task = key_path.clone();
    let watcher_handle = Arc::new(watcher);

    tokio::spawn(async move {
        let debounce_duration = Duration::from_secs(watch_delay_secs as u64);
        let mut reload_deadline: Option<Instant> = None;

        loop {
            tokio::select! {
                // Wait for file change events
                _ = event_rx.recv() => {
                    // Reset debounce timer on each event
                    reload_deadline = Instant::now()
                        .checked_add(debounce_duration)
                        .or_else(|| Instant::now().checked_add(Duration::from_secs(60)));
                }
                _ = async {
                    if let Some(deadline) = reload_deadline {
                        sleep_until(deadline).await;
                    } else {
                        // Wait indefinitely if no reload pending
                        loop {
                            sleep(Duration::from_secs(3600)).await;
                        }
                    }
                } => {
                    if reload_deadline.take().is_some() {
                        match read_certs_and_keys(&cert_path_for_task, &key_path_for_task).await {
                            Ok(certs_keys) => {
                                if let Err(e) = tx.send(Some(certs_keys)) {
                                    warn!("Failed to send certificate update: {}", e);
                                    break;
                                }
                                info!("Certificates reloaded successfully");
                            }
                            Err(e) => {
                                error!(error = %e, "Failed to reload certificates, keeping current ones");
                            }
                        }
                    }
                }
            }
        }
        // Keep watcher alive (drop at end of task)
        drop(watcher_handle);
    });

    Ok(rx)
}
