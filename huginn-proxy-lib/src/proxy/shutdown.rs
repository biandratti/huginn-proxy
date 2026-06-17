//! Cooperative shutdown primitives.
//!
//! ## Shutdown sequence
//!
//! ```text
//! SIGTERM / SIGINT
//!   │
//!   └─▶ shutdown_tx.send(true)          (server.rs)
//!         │
//!         ├─▶ config-watcher task       (config/watcher.rs)
//!         │     shutdown_rx.wait_for(true) → break
//!         │
//!         ├─▶ metrics-server task       (main.rs)
//!         │     shutdown_rx.wait_for(true) → break
//!         │
//!         └─▶ wait_for_drain            (server.rs)
//!               waits for all active HTTP connections to finish,
//!               then ServiceHandle::shutdown() awaits each background task
//! ```
//!
//! Every background task receives a [`ShutdownWatch`] clone and selects on it
//! against its main work loop. [`ServiceHandle`] wraps the resulting
//! `JoinHandle` and is awaited in order during drain.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

/// Canonical shutdown signal type, adapted from Pingora's `ShutdownWatch`.
///
/// Each background task receives a clone and selects on `wait_for(|v| *v)`
/// against its main work. When `true` is sent, tasks exit their loops
/// cooperatively and flush any pending log lines before returning.
pub type ShutdownWatch = watch::Receiver<bool>;

/// The sending half of the shutdown channel.
///
/// Owned at the top level (`main.rs`). Calling `send(true)` broadcasts to
/// every task that holds a `ShutdownWatch` clone.
pub type ShutdownSender = watch::Sender<bool>;

/// Create the shutdown channel initialised to `false` (not shutting down).
pub fn shutdown_channel() -> (ShutdownSender, ShutdownWatch) {
    watch::channel(false)
}

/// Identifies each background service for logging during shutdown.
pub enum ServiceName {
    CertReload,
    ConfigWatcher,
    MetricsServer,
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CertReload => "cert-reload",
            Self::ConfigWatcher => "config-watcher",
            Self::MetricsServer => "metrics-server",
        })
    }
}

/// Handle to a background service that supports cooperative shutdown.
///
/// # Today (single runtime)
/// Wraps a `JoinHandle<()>` in the shared Tokio runtime.
/// `shutdown()` awaits the handle with a timeout.
///
/// # Migration path to multi-runtime. Conditions are already prepared in case of using multi-runtime.
/// Add a `runtime: tokio::runtime::Runtime` field and change `shutdown()` to
/// call `self.runtime.shutdown_timeout(timeout)`, the same mechanism Pingora
/// uses. Every background task's `select!` loop and the `Vec<ServiceHandle>`
/// collection in `run()` stay unchanged; only this impl changes.
pub struct ServiceHandle {
    pub handle: JoinHandle<()>,
    pub name: ServiceName,
}

impl ServiceHandle {
    pub async fn shutdown(self, timeout: Duration) {
        match tokio::time::timeout(timeout, self.handle).await {
            Ok(Ok(())) => info!("{} exited cleanly", self.name),
            Ok(Err(e)) if e.is_panic() => warn!("{} panicked during shutdown", self.name),
            Ok(Err(_)) => {}
            Err(_) => warn!(
                "{} did not exit within {}s; will be cancelled by runtime drop",
                self.name,
                timeout.as_secs()
            ),
        }
    }
}

pub async fn wait_for_drain(
    mut connections_closed_rx: watch::Receiver<()>,
    active_connections: Arc<AtomicUsize>,
    timeout_secs: u64,
) {
    if active_connections.load(Ordering::Relaxed) == 0 {
        info!("All connections closed, shutdown complete");
        return;
    }

    let start = Instant::now();
    let deadline = crate::utils::deadline_from(start, Duration::from_secs(timeout_secs));

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
