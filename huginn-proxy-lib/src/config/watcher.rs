use std::path::PathBuf;

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{sleep, sleep_until, Duration, Instant};
use tracing::{error, info};

use crate::error::ProxyError;

/// Spawn a background task that watches `config_path` for filesystem changes and
/// sends a unit signal on `reload_tx` after each debounced event.
///
/// Activated only when `--watch` is enabled. A single signal is sent per
/// burst of changes (debounced by `watch_delay_secs`).
pub fn spawn_config_watcher(
    config_path: PathBuf,
    reload_tx: UnboundedSender<()>,
    watch_delay_secs: u32,
) -> crate::error::Result<()> {
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

    tokio::spawn(async move {
        let debounce_duration = Duration::from_secs(watch_delay_secs as u64);
        let mut reload_deadline: Option<Instant> = None;
        let _watcher = watcher;

        loop {
            tokio::select! {
                _ = event_rx.recv() => {
                    reload_deadline = Instant::now().checked_add(debounce_duration)
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

    Ok(())
}
