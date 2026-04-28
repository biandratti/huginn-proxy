//! Backend address → shared health state map.
//!
//! [`HealthRegistry`] is the read side of the health check system: handed to
//! the forwarding gate (see [`crate::proxy::forwarding`]) so it can query a
//! backend's status on every request without any coordination with the
//! checker tasks.
//!
//! The map is wrapped in `Arc<RwLock<HashMap<...>>>` for consistency with the
//! existing `SharedRateLimiter` pattern in
//! [`crate::proxy::reload`]. Reads dominate writes by orders of magnitude
//! (every request reads, mutations only happen on hot reload), so the
//! `RwLock` contention is negligible in practice.
//!
//! ## Opt-in behaviour
//!
//! Backends without a `[backends.health_check]` configuration are **not**
//! inserted into the registry. [`HealthRegistry::is_healthy`] returns `true`
//! for any unknown address — health checks are per-backend opt-in; traffic is
//! not gated until a backend registers a probe.

use super::health::UpstreamHealth;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Address → health state map shared between the future `HealthCheckSupervisor`
/// (writer, on hot reload) and the forwarding gate (reader, per request).
#[derive(Debug, Default, Clone)]
pub struct HealthRegistry {
    inner: Arc<RwLock<HashMap<String, Arc<UpstreamHealth>>>>,
}

impl HealthRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the backend is healthy **or** has no health check
    /// configured (address absent from the registry).
    ///
    /// Opt-in: only backends with an active health-check configuration are
    /// registered; unknown addresses are treated as healthy (no gate).
    pub fn is_healthy(&self, address: &str) -> bool {
        match self.inner.read() {
            Ok(map) => map.get(address).is_none_or(|h| h.is_healthy()),
            // Lock poisoning means a checker task panicked. Fail-open so the
            // proxy keeps serving traffic while the operator investigates.
            Err(poisoned) => poisoned
                .into_inner()
                .get(address)
                .is_none_or(|h| h.is_healthy()),
        }
    }

    /// Returns the [`UpstreamHealth`] handle for `address`, creating it (and
    /// inserting it into the map) if absent. Used by the supervisor when starting a probe task.
    pub fn get_or_create(&self, address: &str) -> Arc<UpstreamHealth> {
        let mut map = self.inner.write().unwrap_or_else(|e| e.into_inner());
        map.entry(address.to_string())
            .or_insert_with(|| Arc::new(UpstreamHealth::new()))
            .clone()
    }

    /// Drop the entry for `address`. Used by the supervisor when a probe is
    /// canceled (backend removed or health check disabled via hot reload).
    pub fn remove(&self, address: &str) {
        let mut map = self.inner.write().unwrap_or_else(|e| e.into_inner());
        map.remove(address);
    }

    /// Returns the set of currently registered addresses. Useful for hot
    /// reload diffing and for tests.
    pub fn addresses(&self) -> Vec<String> {
        let map = self.inner.read().unwrap_or_else(|e| e.into_inner());
        map.keys().cloned().collect()
    }

    /// Number of backends currently registered. Mostly useful for tests.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Returns `true` if no backends are registered.
    pub fn is_empty(&self) -> bool {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }
}
