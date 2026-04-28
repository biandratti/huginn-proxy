//! Consecutive success/failure counter with hysteresis.
//!
//! [`ConsecutiveCounter`] is the state-transition engine of the health check
//! system. It tracks streaks of consecutive successes and failures and only
//! emits a state transition when one of two thresholds is crossed:
//!
//! - `unhealthy_threshold` consecutive failures → transition to unhealthy.
//! - `healthy_threshold` consecutive successes → transition back to healthy.
//!
//! Any opposite outcome resets the corresponding streak counter, which is the
//! mechanism that prevents flapping under intermittent failures (e.g. one
//! transient timeout in an otherwise healthy stream).
//!
//! The counter is **not** thread-safe and is meant to be owned by a single
//! health-check task per backend. The shared state visible to the rest of the
//! proxy lives in [`crate::backend::health_check::UpstreamHealth`].

/// Tracks consecutive success/failure counts to determine health state
/// transitions. Only triggers a state change when a threshold is crossed.
pub struct ConsecutiveCounter {
    consecutive_ok: u32,
    consecutive_fail: u32,
    unhealthy_threshold: u32,
    healthy_threshold: u32,
    is_healthy: bool,
}

impl ConsecutiveCounter {
    /// Create a new counter starting in the healthy state ("optimistic boot",
    /// matching [`crate::backend::health_check::UpstreamHealth::new`]).
    ///
    /// Both thresholds are clamped to a minimum of 1 — passing 0 would never
    /// trigger a transition, which is almost certainly a misconfiguration.
    pub fn new(unhealthy_threshold: u32, healthy_threshold: u32) -> Self {
        Self {
            consecutive_ok: 0,
            consecutive_fail: 0,
            unhealthy_threshold: unhealthy_threshold.max(1),
            healthy_threshold: healthy_threshold.max(1),
            is_healthy: true,
        }
    }

    /// Record a check result.
    ///
    /// Returns `Some(new_state)` only when a state transition occurred —
    /// callers use this to update the shared [`crate::backend::health_check::UpstreamHealth`]
    /// flag and emit a metric / log line. Returns `None` for the common case
    /// where the streak grew but no threshold was crossed.
    pub fn record(&mut self, ok: bool) -> Option<bool> {
        if ok {
            self.consecutive_ok = self.consecutive_ok.saturating_add(1);
            self.consecutive_fail = 0;

            if !self.is_healthy && self.consecutive_ok >= self.healthy_threshold {
                self.is_healthy = true;
                self.consecutive_ok = 0;
                return Some(true);
            }
        } else {
            self.consecutive_fail = self.consecutive_fail.saturating_add(1);
            self.consecutive_ok = 0;

            if self.is_healthy && self.consecutive_fail >= self.unhealthy_threshold {
                self.is_healthy = false;
                self.consecutive_fail = 0;
                return Some(false);
            }
        }
        None
    }

    /// Current state as tracked by this counter.
    pub fn is_healthy(&self) -> bool {
        self.is_healthy
    }
}
