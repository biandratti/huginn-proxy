//! Readiness state shared between the proxy and the observability server's `/ready`
//! endpoint.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Tracks whether the proxy is ready to accept traffic.
///
/// Cheaply cloneable (shared `Arc`). The proxy flips it ready once its listeners are
/// accepting connections and back to not-ready during graceful shutdown; the `/ready`
/// endpoint reads it. Readiness reflects internal process state only and is deliberately
/// independent of backend availability.
#[derive(Clone, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    /// Create a new handle in the not-ready state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the proxy as ready to accept traffic (`/ready` -> 200).
    pub fn mark_ready(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Mark the proxy as not ready (`/ready` -> 503), e.g. during graceful shutdown.
    pub fn mark_not_ready(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// Whether the proxy is currently ready to accept traffic.
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
