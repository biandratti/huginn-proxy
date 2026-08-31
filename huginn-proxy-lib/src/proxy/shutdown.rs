//! Cooperative shutdown primitives.
//!
//! ## Shutdown sequence
//!
//! ```text
//! SIGTERM / SIGINT
//!   │
//!   ├─▶ phase = Draining                (server.rs)  /ready = 503
//!   │     accept loops keep running
//!   │     sleep drain_delay_secs (second signal skips)
//!   │
//!   ├─▶ phase = Stopping
//!   │     │
//!   │     ├─▶ accept loops              wait_for(Stopping) → break
//!   │     ├─▶ config-watcher            wait_for(Stopping) → break
//!   │     ├─▶ ebpf-reconnect            wait_for(Stopping) → break
//!   │     └─▶ connections               graceful_shutdown() then wait_for_drain
//!   │
//!   └─▶ observability server            stopped by main.rs after run() returns
//! ```
//!
//! Every background task receives a [`ShutdownWatch`] clone and selects on
//! [`ShutdownPhase::Stopping`]. [`ServiceHandle`] wraps the resulting
//! `JoinHandle` and is awaited in order during drain.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

/// Two-phase process lifetime. `Draining` fails readiness but keeps accepting;
/// `Stopping` closes the listen socket and GOAWAYs existing connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    Running,
    Draining,
    Stopping,
}

impl ShutdownPhase {
    /// Tasks that must keep working through drain wait for this.
    pub fn is_stopping(self) -> bool {
        matches!(self, Self::Stopping)
    }
}

/// Canonical shutdown signal type, adapted from Pingora's `ShutdownWatch`.
///
/// Each background task receives a clone and selects on
/// `wait_for(|phase| phase.is_stopping())`.
pub type ShutdownWatch = watch::Receiver<ShutdownPhase>;

/// The sending half of the shutdown channel.
///
/// Owned at the top level (`main.rs`). Broadcasts [`ShutdownPhase`] to every
/// task that holds a [`ShutdownWatch`] clone.
pub type ShutdownSender = watch::Sender<ShutdownPhase>;

/// Create the shutdown channel initialised to [`ShutdownPhase::Running`].
pub fn shutdown_channel() -> (ShutdownSender, ShutdownWatch) {
    watch::channel(ShutdownPhase::Running)
}

/// Identifies each background service for logging during shutdown.
pub enum ServiceName {
    CertReload,
    ConfigWatcher,
    EbpfReconnect,
    MetricsServer,
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CertReload => "cert-reload",
            Self::ConfigWatcher => "config-watcher",
            Self::EbpfReconnect => "ebpf-reconnect",
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

/// Wait until `active_connections` is 0 or `timeout_secs` elapses.
///
/// Clears a stale `changed()` notification first so closures that happened
/// before phase 2 cannot release the drain early.
pub async fn wait_for_drain(
    mut connections_closed_rx: watch::Receiver<()>,
    active_connections: Arc<AtomicUsize>,
    timeout_secs: u64,
) {
    connections_closed_rx.borrow_and_update();

    if active_connections.load(Ordering::Relaxed) == 0 {
        info!("All connections closed, shutdown complete");
        return;
    }

    let start = Instant::now();
    let deadline = crate::utils::deadline_from(start, Duration::from_secs(timeout_secs));

    loop {
        let active = active_connections.load(Ordering::Relaxed);
        if active == 0 {
            info!("All connections closed, shutdown complete");
            return;
        }
        if Instant::now() >= deadline {
            warn!(
                active_connections = active,
                "Shutdown timeout reached, {active} connections still active"
            );
            return;
        }

        tokio::select! {
            changed = connections_closed_rx.changed() => {
                if changed.is_err() {
                    let remaining = active_connections.load(Ordering::Relaxed);
                    if remaining == 0 {
                        info!("All connections closed, shutdown complete");
                    } else {
                        warn!(
                            active_connections = remaining,
                            "Connection-closed watch closed with {remaining} connections still active"
                        );
                    }
                    return;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}
