pub mod backend;
pub mod headers;
pub mod security;

pub use backend::{
    Backend, BackendHttpVersion, BackendPoolConfig, HealthCheckConfig, HealthCheckType, Route,
};
pub use headers::{CustomHeader, HeaderManipulation, HeaderManipulationGroup};
pub use security::{
    CspConfig, HstsConfig, IpFilterConfig, IpFilterMode, LimitBy, RateLimitConfig,
    RouteRateLimitConfig, SecurityConfig, SecurityDynamicConfig, SecurityHeaders,
};

/// Runtime configuration that can be hot-reloaded atomically via ArcSwap.
///
/// Contains all fields that control routing and policy decisions per-request.
/// These can change at runtime without restarting the process or dropping
/// existing connections. Constructed from `Config::into_parts()`, not
/// deserialized directly from TOML.
#[derive(Debug, Clone, PartialEq)]
pub struct DynamicConfig {
    /// List of backend servers
    pub backends: Vec<Backend>,
    /// Path-based routing rules
    pub routes: Vec<Route>,
    /// Preserve the original Host header from clients when forwarding
    pub preserve_host: bool,
    /// Global header manipulation applied to all requests/responses
    pub headers: Option<HeaderManipulation>,
    /// Dynamic security policy (headers, IP filter, rate limits)
    pub security: SecurityDynamicConfig,
    /// Backend connection pool settings (idle timeout, max idle connections per host)
    pub backend_pool: BackendPoolConfig,
}
