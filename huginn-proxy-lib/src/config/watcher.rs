use crate::error::ProxyError;
use crate::proxy::shutdown::{ServiceHandle, ServiceName, ShutdownWatch};
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{sleep_until, Duration, Instant};
use tracing::{error, info};

/// Spawn a background task that watches `config_path` for filesystem changes and
/// sends a unit signal on `reload_tx` after each debounced event.
///
/// Activated only when `[reload].watch` is enabled. A single signal is sent per
/// burst of changes (debounced by `[reload].debounce_secs`).
///
/// The returned [`ServiceHandle`] must be awaited during graceful shutdown
/// (after signalling via [`crate::proxy::shutdown::ShutdownSender`]) to ensure
/// teardown logs are flushed before tracing is torn down.
///
/// ## Watch strategy
///
/// Two watches are registered:
/// - **Parent directory** catches atomic saves (editor writes a temp file and
///   renames it into place, generating a `Create`/`Modify` event in the dir).
/// - **Config file directly** catches in-place writes through single-file bind
///   mounts (Docker, Kubernetes `hostPath`/`ConfigMap` subPath, Podman, etc.):
///   the container sees the host inode directly, but the parent directory is an
///   overlayfs layer that does not propagate inotify events to the mounted file.
pub fn spawn_config_watcher(
    config_path: PathBuf,
    reload_tx: UnboundedSender<()>,
    debounce_secs: u32,
    mut shutdown_rx: ShutdownWatch,
) -> crate::error::Result<ServiceHandle> {
    let config_path_for_watcher = config_path.clone();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    let mut watcher = RecommendedWatcher::new(
        move |result: Result<notify::Event, notify::Error>| {
            if let Ok(event) = result {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    let is_config = event.paths.iter().any(|p| p == &config_path_for_watcher);
                    if is_config {
                        let _ = event_tx.send(());
                    }
                }
            }
        },
        Config::default(),
    )
    .map_err(|e| ProxyError::Config(format!("Failed to create config watcher: {e}")))?;

    let parent_dir = config_path
        .parent()
        .ok_or_else(|| ProxyError::Config("Config path has no parent directory".to_string()))?;
    watcher
        .watch(parent_dir, RecursiveMode::NonRecursive)
        .map_err(|e| ProxyError::Config(format!("Failed to watch config directory: {e}")))?;

    if let Err(e) = watcher.watch(&config_path, RecursiveMode::NonRecursive) {
        error!(
            path = %config_path.display(),
            error = %e,
            "Could not watch config file directly (parent-dir watch still active)"
        );
    }

    info!(
        path = %config_path.display(),
        debounce_secs,
        "Config watcher started, watching for file changes"
    );

    let handle = tokio::spawn(async move {
        let debounce_duration = Duration::from_secs(debounce_secs as u64);
        let mut reload_deadline: Option<Instant> = None;
        let _watcher = watcher;

        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.wait_for(|v| *v) => {
                    info!("Config watcher task shutting down");
                    break;
                }
                _ = event_rx.recv() => {
                    info!(path = %config_path.display(), debounce_secs, "Config file change detected, reload scheduled");
                    reload_deadline = Some(crate::utils::deadline_from(Instant::now(), debounce_duration));
                }
                _ = async {
                    match reload_deadline {
                        Some(deadline) => sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                } => {
                    if reload_deadline.take().is_some() {
                        info!("Config file changed, triggering reload");
                        if reload_tx.send(()).is_err() {
                            error!("Config reload channel closed, stopping watcher");
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(ServiceHandle { handle, name: ServiceName::ConfigWatcher })
}
