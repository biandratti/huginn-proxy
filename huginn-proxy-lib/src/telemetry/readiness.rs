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

/// Shared state behind the observability server's `/ready` endpoint.
///
/// Cheap to clone (`Arc` inside). `run()` holds one handle and the observability server
/// another; both observe the same state.
///
/// # Lifecycle
///
/// ```text
/// new()           503 proxy_starting
/// mark_ready()    200                   listeners bound (server.rs)
/// mark_draining() 503 proxy_draining    SIGTERM; listeners keep accepting
/// ```
///
/// Draining is terminal: `mark_ready()` cannot undo it. Readiness only fails the probe so
/// the load balancer stops sending new traffic; closing the listen socket is
/// [`ShutdownPhase::Stopping`](crate::proxy::shutdown::ShutdownPhase::Stopping)'s job, one
/// `timeout.drain_delay_secs` later. Letting readiness flip back to 200 inside that window
/// would hand traffic to a process about to stop accepting.
///
/// ```
/// use huginn_proxy_lib::{NotReadyReason, Readiness};
///
/// let readiness = Readiness::new();
/// assert_eq!(readiness.not_ready_reason(), Some(NotReadyReason::ProxyStarting));
///
/// readiness.mark_ready();
/// assert!(readiness.is_ready());
///
/// readiness.mark_draining();
/// assert_eq!(readiness.not_ready_reason(), Some(NotReadyReason::ProxyDraining));
///
/// readiness.mark_ready();
/// assert_eq!(readiness.not_ready_reason(), Some(NotReadyReason::ProxyDraining));
/// ```
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
    ///
    /// Does not clear `draining`: once shutdown starts there is no way back to 200.
    pub fn mark_ready(&self) {
        self.0.ready.store(true, Ordering::Release);
    }

    /// Fail `/ready` with `proxy_draining` while listeners still accept.
    ///
    /// Terminal: no other method leaves this state.
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
    ///
    /// Draining is checked first so it outranks every other reason.
    pub fn not_ready_reason(&self) -> Option<NotReadyReason> {
        if self.0.draining.load(Ordering::Acquire) {
            return Some(NotReadyReason::ProxyDraining);
        }
        if self.0.ready.load(Ordering::Acquire) {
            None
        } else {
            Some(NotReadyReason::ProxyStarting)
        }
    }
}
