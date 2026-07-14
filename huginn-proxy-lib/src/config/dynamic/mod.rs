pub mod backend;
pub mod headers;
pub mod security;
pub use backend::{
    sort_domain_routes, sort_routes, Backend, BackendHttpVersion, BackendPoolConfig, Domain,
    HealthCheckConfig, HealthCheckType, Route, DEFAULT_DOMAIN_LABEL, DEFAULT_FINGERPRINTING,
};
pub use headers::{CustomHeader, HeaderManipulation, HeaderManipulationGroup};
pub use security::{
    CspConfig, DomainSecurityConfig, HstsConfig, IpFilterConfig, IpFilterMode, LimitBy,
    RateLimitConfig, RouteSecurityConfig, SecurityConfig, SecurityDynamicConfig, SecurityHeaders,
};

use backend::{BackendPoolView, BackendView, DomainView};
use headers::HeaderManipulationView;
use security::SecurityView;
use serde::Serialize;
use std::sync::Arc;

/// Runtime configuration that can be hot-reloaded atomically via ArcSwap.
///
/// Contains all fields that control routing and policy decisions per-request.
/// These can change at runtime without restarting the process or dropping
/// existing connections. Constructed from `Config::into_parts()`, not
/// deserialized directly from TOML.
#[derive(Debug, Clone, PartialEq)]
pub struct DynamicConfig {
    /// List of backend servers
    pub backends: Arc<Vec<Backend>>,
    /// Domain entries, each groups a TLS cert with its path-based routes
    pub domains: Arc<Vec<Domain>>,
    /// Preserve the original Host header from clients when forwarding
    pub preserve_host: bool,
    /// Global header manipulation applied to all requests/responses
    pub headers: Option<HeaderManipulation>,
    /// Dynamic security policy (headers, IP filter, rate limits)
    pub security: SecurityDynamicConfig,
    /// Backend connection pool settings (idle timeout, max idle connections per host)
    pub backend_pool: BackendPoolConfig,
}

/// Allowlisted effective-config view of [`DynamicConfig`]. Each section mirrors one config type;
/// the corresponding `*View` struct lives next to that type in the submodules above.
#[derive(Serialize)]
pub(crate) struct DynamicView<'a> {
    backends: Vec<BackendView<'a>>,
    domains: Vec<DomainView<'a>>,
    preserve_host: bool,
    headers: Option<HeaderManipulationView<'a>>,
    security: SecurityView<'a>,
    backend_pool: BackendPoolView,
}

impl DynamicConfig {
    pub(crate) fn effective_view(&self) -> DynamicView<'_> {
        DynamicView {
            backends: self.backends.iter().map(Backend::effective_view).collect(),
            domains: self.domains.iter().map(Domain::effective_view).collect(),
            preserve_host: self.preserve_host,
            headers: self
                .headers
                .as_ref()
                .map(HeaderManipulation::effective_view),
            security: self.security.effective_view(),
            backend_pool: self.backend_pool.effective_view(),
        }
    }
}
