use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::watch;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

pub async fn wait_for_drain(
    mut connections_closed_rx: watch::Receiver<()>,
    active_connections: Arc<AtomicUsize>,
    timeout_secs: u64,
) {
    let start = Instant::now();
    let deadline = start
        .checked_add(Duration::from_secs(timeout_secs))
        .unwrap_or_else(|| start.checked_add(Duration::from_secs(60)).unwrap_or(start));

    let timed_out = tokio::select! {
        _ = connections_closed_rx.changed() => false,
        _ = tokio::time::sleep_until(deadline) => true,
    };

    let active = active_connections.load(Ordering::Relaxed);
    if active == 0 {
        info!("All connections closed, shutdown complete");
    } else if timed_out {
        warn!(
            active_connections = active,
            "Shutdown timeout reached, {} connections still active", active
        );
    } else {
        warn!(
            active_connections = active,
            "Connection closed notification received but {} connections still active", active
        );
    }
}
