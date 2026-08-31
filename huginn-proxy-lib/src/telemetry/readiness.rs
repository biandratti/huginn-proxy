//! Readiness state shared between the proxy and the observability server's `/ready` endpoint.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Why `/ready` is 503. Serialized as the JSON `reason` snake_case string at the HTTP edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReadyReason {
    ProxyStarting,
    ProxyDraining,
}

impl NotReadyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProxyStarting => "proxy_starting",
            Self::ProxyDraining => "proxy_draining",
        }
    }
}

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

    /// Whether `/ready` would return 200. Same source of truth as the HTTP probe
    /// (`not_ready_reason`).
    pub fn is_ready(&self) -> bool {
        self.not_ready_reason().is_none()
    }

    /// `None` when ready; otherwise why `/ready` is 503.
    pub fn not_ready_reason(&self) -> Option<NotReadyReason> {
        if self.0.ready.load(Ordering::Acquire) {
            return None;
        }
        if self.0.draining.load(Ordering::Acquire) {
            Some(NotReadyReason::ProxyDraining)
        } else {
            Some(NotReadyReason::ProxyStarting)
        }
    }
}
