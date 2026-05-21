use crate::config::{ClientAuth, SessionResumptionConfig, TlsConfig, TlsOptions};
use crate::error::ProxyError;
use crate::tls::acceptor::build_server_config;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::watch;
use tokio::time::{sleep, sleep_until, Duration, Instant};
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
    /// Build a `TlsAcceptor` from these certs, honoring the full TLS config
    /// (cipher suites, ALPN, client auth, session resumption).
    ///
    /// Delegates to `build_server_config` so the reload path and the startup
    /// path produce identical `ServerConfig`s for the same inputs.
    pub fn build_tls_acceptor(
        &self,
        alpn: &[String],
        options: &TlsOptions,
        client_auth: &ClientAuth,
        session_resumption: &SessionResumptionConfig,
    ) -> crate::error::Result<TlsAcceptor> {
        let server = build_server_config(
            self.certs.to_vec(),
            self.key.clone_key(),
            alpn,
            options,
            client_auth,
            session_resumption,
        )?;
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

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| ProxyError::Tls(format!("Unable to parse the certificates: {e}")))?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();

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
        .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| ProxyError::Tls(format!("Unable to parse the private keys: {e}")))?
        .into_iter()
        .map(|k| k.clone_key())
        .collect();

    let key = keys.pop().ok_or_else(|| {
        ProxyError::Tls(
            "No private keys found - Make sure they are in PKCS#8/PEM format".to_string(),
        )
    })?;

    Ok(ServerCertsKeys { certs, key })
}

/// Load certificates once and return a static receiver, no filesystem watching.
///
/// The sender is kept alive in a detached task that never terminates, so the
/// channel stays open for the lifetime of the process. If we dropped it, any
/// consumer calling `rx.changed().await` would receive `Err(RecvError)`
/// immediately and could spin if the error is ignored.
async fn load_certs_static(
    cert_path: &Path,
    key_path: &Path,
) -> Result<watch::Receiver<Option<ServerCertsKeys>>, ProxyError> {
    let certs_keys = read_certs_and_keys(cert_path, key_path).await?;
    let (tx, rx) = watch::channel(Some(certs_keys));
    tokio::spawn(async move {
        let _tx = tx;
        std::future::pending::<()>().await;
    });
    Ok(rx)
}

/// Load certificates and spawn a background watcher that reloads them on file changes.
async fn load_certs_with_watch(
    cert_path: PathBuf,
    key_path: PathBuf,
    watch_delay_secs: u32,
) -> Result<watch::Receiver<Option<ServerCertsKeys>>, ProxyError> {
    let initial_certs_keys = read_certs_and_keys(&cert_path, &key_path).await?;
    let (tx, rx) = watch::channel(Some(initial_certs_keys));

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    let cert_path_for_watcher = cert_path.clone();
    let key_path_for_watcher = key_path.clone();
    let mut watcher = RecommendedWatcher::new(
        move |result: Result<notify::Event, notify::Error>| {
            if let Ok(event) = result {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    let is_cert_file = event.paths.iter().any(|p| p == &cert_path_for_watcher);
                    let is_key_file = event.paths.iter().any(|p| p == &key_path_for_watcher);
                    if is_cert_file || is_key_file {
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

    let cert_path_for_task = cert_path.clone();
    let key_path_for_task = key_path.clone();
    let watcher_handle = Arc::new(watcher);

    tokio::spawn(async move {
        let debounce_duration = Duration::from_secs(watch_delay_secs as u64);
        let mut reload_deadline: Option<Instant> = None;

        loop {
            tokio::select! {
                _ = event_rx.recv() => {
                    reload_deadline = Instant::now()
                        .checked_add(debounce_duration)
                        .or_else(|| Instant::now().checked_add(Duration::from_secs(60)));
                }
                _ = async {
                    if let Some(deadline) = reload_deadline {
                        sleep_until(deadline).await;
                    } else {
                        loop { sleep(Duration::from_secs(3600)).await; }
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
        drop(watcher_handle);
    });

    Ok(rx)
}

/// Build a certificate receiver, with or without filesystem watching.
///
/// - `watch = false`: certificates are loaded once at startup, never reloaded.
/// - `watch = true`: a background watcher monitors cert/key files and reloads on changes,
///   debounced by `watch_delay_secs`.
pub async fn build_cert_reloader(
    tls_config: &TlsConfig,
    watch: bool,
    watch_delay_secs: u32,
) -> Result<watch::Receiver<Option<ServerCertsKeys>>, ProxyError> {
    let cert_path = PathBuf::from(&tls_config.cert_path);
    let key_path = PathBuf::from(&tls_config.key_path);

    if watch {
        load_certs_with_watch(cert_path, key_path, watch_delay_secs).await
    } else {
        load_certs_static(&cert_path, &key_path).await
    }
}
