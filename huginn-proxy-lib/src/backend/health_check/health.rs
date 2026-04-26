//! Shared health state for a single upstream.
//!
//! [`UpstreamHealth`] is the smallest unit of health tracking: a single
//! [`AtomicBool`] flag accessed concurrently by:
//!
//! - **The health checker task** (writer): updates the flag whenever a state
//!   transition is detected by the `ConsecutiveCounter` helper in the same
//!   `health_check` module.
//! - **The forwarding gate** (readers): reads the flag on every request to
//!   decide whether to short-circuit with a 502 Bad Gateway.
//!
//! `Relaxed` ordering is sufficient because eventual consistency is acceptable
//! for health checks: a stale read for a few microseconds during a transition
//! does not change the observable behaviour (one extra request to a backend
//! about to be marked unhealthy, or one fewer request to a backend about to
//! recover — both are inside the noise floor of the probe interval).

use std::sync::atomic::{AtomicBool, Ordering};

/// Shared health state for a single upstream, accessed by both the health
/// checker task (writer) and request handlers (readers) via `Arc`.
#[derive(Debug)]
pub struct UpstreamHealth {
    healthy: AtomicBool,
}

impl UpstreamHealth {
    /// Create a new health state, initialized as healthy ("optimistic boot").
    ///
    /// Starting healthy lets traffic flow as soon as the proxy boots, instead
    /// of forcing every backend to wait `unhealthy_threshold * interval` seconds
    /// before being usable. The first failed probes will mark it unhealthy if
    /// the backend is actually down.
    pub fn new() -> Self {
        Self { healthy: AtomicBool::new(true) }
    }

    /// Returns the current health status.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Set the health status. Called only by the health checker task on
    /// state transitions (not on every probe).
    pub fn set(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::Relaxed);
    }
}

impl Default for UpstreamHealth {
    fn default() -> Self {
        Self::new()
    }
}
