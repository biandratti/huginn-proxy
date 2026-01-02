use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::watch;
use tracing::warn;

use crate::config::SecurityConfig;
use crate::telemetry::Metrics;

use super::guards::ConnectionGuard;

/// Errors that can occur when trying to accept a connection
#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("Server is shutting down")]
    Shutdown,
    #[error("Connection limit exceeded (current: {current}, limit: {limit})")]
    LimitExceeded { current: usize, limit: usize },
}

/// Manages connection limits and lifecycle
pub struct ConnectionManager {
    active_connections: Arc<AtomicUsize>,
    max_connections: usize,
    shutdown_signal: Arc<AtomicUsize>,
    connections_closed_tx: watch::Sender<()>,
}

impl ConnectionManager {
    pub fn new(
        security: &SecurityConfig,
        shutdown_signal: Arc<AtomicUsize>,
        connections_closed_tx: watch::Sender<()>,
    ) -> Self {
        Self {
            active_connections: Arc::new(AtomicUsize::new(0)),
            max_connections: security.max_connections,
            shutdown_signal,
            connections_closed_tx,
        }
    }

    /// Get the active connections counter (for metrics)
    pub fn active_connections(&self) -> Arc<AtomicUsize> {
        self.active_connections.clone()
    }

    /// Check if shutdown was requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown_signal.load(Ordering::Relaxed) == 1
    }

    /// Try to accept a new connection
    /// Returns Ok(guard) if connection is accepted, Err(ConnectionError) if rejected
    pub fn try_accept(
        &self,
        peer: std::net::SocketAddr,
        metrics: Option<&Arc<Metrics>>,
    ) -> Result<ConnectionGuard, ConnectionError> {
        // Check if shutdown was requested
        if self.is_shutdown() {
            return Err(ConnectionError::Shutdown);
        }

        // Check connection limit (DoS protection)
        let current_connections = self.active_connections.load(Ordering::Relaxed);
        if current_connections >= self.max_connections {
            if let Some(m) = metrics {
                m.connections_rejected_total.add(1, &[]);
            }
            warn!(
                current = current_connections,
                limit = self.max_connections,
                peer = %peer,
                "Connection limit exceeded, rejecting connection"
            );
            return Err(ConnectionError::LimitExceeded {
                current: current_connections,
                limit: self.max_connections,
            });
        }

        self.active_connections.fetch_add(1, Ordering::Relaxed);

        if let Some(m) = metrics {
            m.connections_total.add(1, &[]);
            m.connections_active.add(1, &[]);
        }

        Ok(ConnectionGuard::new(
            self.active_connections.clone(),
            self.connections_closed_tx.clone(),
            metrics.map(|m| m.connections_active.clone()),
        ))
    }
}
