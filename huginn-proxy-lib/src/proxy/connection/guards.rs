use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::watch;

/// Guard to decrement active connections counter when dropped
/// Also notifies when the last connection closes (for graceful shutdown)
pub struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
    notifier: Option<watch::Sender<()>>,
    connections_active: Option<opentelemetry::metrics::UpDownCounter<i64>>,
}

impl ConnectionGuard {
    pub fn new(
        counter: Arc<AtomicUsize>,
        notifier: watch::Sender<()>,
        connections_active: Option<opentelemetry::metrics::UpDownCounter<i64>>,
    ) -> Self {
        Self { counter, notifier: Some(notifier), connections_active }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let remaining = self.counter.fetch_sub(1, Ordering::Relaxed);
        // Decrement metrics counter
        if let Some(ref counter) = self.connections_active {
            counter.add(-1, &[]);
        }
        // Notify when the last connection closes
        if remaining == 1 {
            if let Some(ref tx) = self.notifier {
                let _ = tx.send(());
            }
        }
    }
}

/// Guard to decrement TLS connection metrics counter when dropped
/// Note: Does NOT decrement the main active_connections counter, as that's handled by ConnectionGuard
pub struct TlsConnectionGuard {
    tls_active: Option<opentelemetry::metrics::UpDownCounter<i64>>,
}

impl TlsConnectionGuard {
    pub fn new(tls_active: Option<opentelemetry::metrics::UpDownCounter<i64>>) -> Self {
        Self { tls_active }
    }
}

impl Drop for TlsConnectionGuard {
    fn drop(&mut self) {
        if let Some(ref counter) = self.tls_active {
            counter.add(-1, &[]);
        }
    }
}
