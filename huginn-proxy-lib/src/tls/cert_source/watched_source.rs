use std::path::PathBuf;
use std::sync::Arc;

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, Duration, Instant};
use tracing::{error, info, warn};

use crate::error::ProxyError;
use crate::proxy::shutdown::ShutdownWatch;

use super::{read_certs_and_keys, ServerCertsKeys};

/// Certificates with a filesystem watcher that publishes updates when the
/// cert or key files change.
///
/// On drop, the inotify watcher and the debounce task are torn down, the
/// `watch::Sender` is dropped, and any subscriber waiting on `changed()`
/// receives `Err(RecvError)`.
pub struct WatchedCertSource {
    rx: watch::Receiver<Arc<ServerCertsKeys>>,
    /// Owns the inotify handle; dropped when the source is dropped.
    _watcher: RecommendedWatcher,
    /// Owns the `watch::Sender`; aborted on drop.
    _task: AbortOnDrop,
}

/// Aborts the wrapped task when dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl WatchedCertSource {
    pub async fn watch(
        cert_path: PathBuf,
        key_path: PathBuf,
        watch_delay_secs: u32,
        mut shutdown_rx: ShutdownWatch,
    ) -> Result<Self, ProxyError> {
        let initial = Arc::new(read_certs_and_keys(&cert_path, &key_path).await?);
        let (tx, rx) = watch::channel(initial);

        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

        let cert_path_for_watcher = cert_path.clone();
        let key_path_for_watcher = key_path.clone();
        let mut watcher = RecommendedWatcher::new(
            move |result: Result<notify::Event, notify::Error>| {
                if let Ok(event) = result {
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        let is_cert = event.paths.iter().any(|p| p == &cert_path_for_watcher);
                        let is_key = event.paths.iter().any(|p| p == &key_path_for_watcher);
                        if is_cert || is_key {
                            let _ = event_tx.send(());
                        }
                    }
                }
            },
            Config::default(),
        )
        .map_err(|e| ProxyError::Tls(format!("Failed to create filesystem watcher: {e}")))?;

        let parent_dir = cert_path.parent().ok_or_else(|| {
            ProxyError::Tls("Certificate path has no parent directory".to_string())
        })?;
        watcher
            .watch(parent_dir, RecursiveMode::NonRecursive)
            .map_err(|e| ProxyError::Tls(format!("Failed to watch certificate directory: {e}")))?;

        let cert_path_for_task = cert_path.clone();
        let key_path_for_task = key_path.clone();
        let task = tokio::spawn(async move {
            let debounce_duration = Duration::from_secs(watch_delay_secs as u64);
            let mut reload_deadline: Option<Instant> = None;

            loop {
                tokio::select! {
                    biased;
                    result = shutdown_rx.changed() => {
                        if result.is_err() || *shutdown_rx.borrow() {
                            info!("Certificate debounce task shutting down");
                            break;
                        }
                    }
                    msg = event_rx.recv() => {
                        if msg.is_none() {
                            error!(
                                cert_path = %cert_path_for_task.display(),
                                "Certificate watcher event channel closed unexpectedly; debounce task exiting"
                            );
                            break;
                        }
                        reload_deadline = Some(crate::utils::deadline_from(Instant::now(), debounce_duration));
                    }
                    _ = async {
                        match reload_deadline {
                            Some(deadline) => sleep_until(deadline).await,
                            None => std::future::pending().await,
                        }
                    } => {
                        if reload_deadline.take().is_some() {
                            match read_certs_and_keys(&cert_path_for_task, &key_path_for_task).await {
                                Ok(certs_keys) => {
                                    if let Err(e) = tx.send(Arc::new(certs_keys)) {
                                        warn!("Failed to publish certificate update to subscribers: {}", e);
                                        break;
                                    }
                                    info!(
                                        cert_path = %cert_path_for_task.display(),
                                        "Certificate files re-read from disk and published to subscribers"
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        error = %e,
                                        cert_path = %cert_path_for_task.display(),
                                        "Failed to re-read certificate files, keeping current ones"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(Self { rx, _watcher: watcher, _task: AbortOnDrop(task) })
    }

    pub(super) fn current(&self) -> Arc<ServerCertsKeys> {
        self.rx.borrow().clone()
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<Arc<ServerCertsKeys>> {
        self.rx.clone()
    }
}
