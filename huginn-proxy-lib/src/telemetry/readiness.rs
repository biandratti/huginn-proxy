//! Readiness state shared between the proxy and the observability server's `/ready` endpoint.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct Inner {
    ready: AtomicBool,
    draining: AtomicBool,
}

#[derive(Clone)]
pub struct Readiness(Arc<Inner>);

impl Default for Readiness {
    fn default() -> Self {
        Self(Arc::new(Inner {
            ready: AtomicBool::new(false),
            draining: AtomicBool::new(false),
        }))
    }
}

impl Readiness {
    /// Create a new handle in the not-ready state (`proxy_starting`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the proxy as ready to accept traffic (`/ready` -> 200).
    pub fn mark_ready(&self) {
        self.0.draining.store(false, Ordering::Release);
        self.0.ready.store(true, Ordering::Release);
    }

    /// Mark the proxy as not ready (`/ready` -> 503), e.g. during graceful shutdown.
    pub fn mark_not_ready(&self) {
        self.0.ready.store(false, Ordering::Release);
    }

    /// Fail `/ready` with `proxy_draining` while listeners still accept.
    pub fn mark_draining(&self) {
        self.0.draining.store(true, Ordering::Release);
        self.0.ready.store(false, Ordering::Release);
    }

    /// Whether the proxy is currently ready to accept traffic.
    pub fn is_ready(&self) -> bool {
        self.0.ready.load(Ordering::Acquire)
    }

    /// `None` when ready; otherwise the `/ready` JSON `reason`.
    pub fn not_ready_reason(&self) -> Option<&'static str> {
        if self.0.ready.load(Ordering::Acquire) {
            return None;
        }
        if self.0.draining.load(Ordering::Acquire) {
            Some("proxy_draining")
        } else {
            Some("proxy_starting")
        }
    }
}
