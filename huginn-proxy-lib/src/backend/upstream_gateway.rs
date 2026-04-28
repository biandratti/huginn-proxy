use std::sync::Arc;

use super::{BackendSelector, HealthRegistry};

/// Combines selection and health-gate into a single forwarding context.
///
/// Wraps the two `Arc`s that drive upstream selection: the
/// [`BackendSelector`] (round-robin algorithm) and the [`HealthRegistry`]
/// (per-backend health state). Cheap to clone — both fields are `Arc`.
#[derive(Clone)]
pub struct UpstreamGateway {
    pub health: Arc<HealthRegistry>,
    pub selector: Arc<BackendSelector>,
}

impl UpstreamGateway {
    pub fn new(health: Arc<HealthRegistry>, selector: Arc<BackendSelector>) -> Self {
        Self { health, selector }
    }
}
