use std::collections::HashMap;
use std::sync::RwLock;

use crate::backend::health_check::HealthRegistry;

use super::round_robin::RoundRobin;

/// Selects one healthy backend among route candidates using the currently configured strategy.
///
/// The selector is intentionally lightweight and lock contention is negligible in
/// practice: one read lock per request and a write lock only on first use of a prefix.
#[derive(Default)]
pub struct BackendSelector {
    rr_by_prefix: RwLock<HashMap<String, RoundRobin>>,
}

impl BackendSelector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Choose one backend address among route candidates.
    ///
    /// - Candidates are filtered by `health_registry` (active health checks).
    /// - If exactly one healthy candidate remains, return it directly.
    /// - If multiple healthy candidates remain, pick one with per-prefix round-robin.
    /// - If no candidate is healthy (or the list is empty), return `None`.
    pub fn select(
        &self,
        route_prefix: &str,
        candidates: &[&str],
        health_registry: &HealthRegistry,
    ) -> Option<String> {
        let healthy: Vec<&str> = candidates
            .iter()
            .copied()
            .filter(|addr| health_registry.is_healthy(addr))
            .collect();

        match healthy.len() {
            0 => None,
            1 => Some(healthy[0].to_string()),
            len => {
                let idx = self.get_or_create_rr(route_prefix).next(len);
                Some(healthy[idx].to_string())
            }
        }
    }

    fn get_or_create_rr(&self, route_prefix: &str) -> RoundRobin {
        if let Ok(map) = self.rr_by_prefix.read() {
            if let Some(rr) = map.get(route_prefix) {
                return rr.clone();
            }
        }

        let mut map = self.rr_by_prefix.write().unwrap_or_else(|e| e.into_inner());
        map.entry(route_prefix.to_string()).or_default().clone()
    }
}
