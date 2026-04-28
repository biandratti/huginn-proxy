use std::collections::HashSet;

use serde::Deserialize;

use super::dynamic::backend::{Backend, BackendPoolConfig, Route};
use super::dynamic::headers::HeaderManipulation;
use super::dynamic::security::{SecurityConfig, SecurityDynamicConfig};
use super::dynamic::DynamicConfig;
use super::startup::fingerprinting::FingerprintConfig;
use super::startup::listen::ListenConfig;
use super::startup::telemetry::{LoggingConfig, TelemetryConfig};
use super::startup::timeout::TimeoutConfig;
use super::startup::tls::TlsConfig;
use super::startup::StaticConfig;

/// Main configuration structure — the TOML deserialization target.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Listener configuration (addresses and socket options)
    pub listen: ListenConfig,
    /// List of backend servers for load balancing
    /// At least one backend is required
    pub backends: Vec<Backend>,
    /// Path-based routing rules (optional)
    /// If no routes match, requests return 404
    #[serde(default)]
    pub routes: Vec<Route>,
    /// Preserve the original Host header from clients when forwarding to backends
    /// When true: Backend receives the original Host header (useful for virtual hosting)
    /// When false: Backend receives the backend address as Host header (default)
    /// Default: false
    #[serde(default)]
    pub preserve_host: bool,
    /// TLS termination configuration (optional)
    /// If not provided, proxy operates in plain HTTP mode
    /// Default: None
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Fingerprinting configuration
    /// Controls which fingerprinting features are enabled
    #[serde(default)]
    pub fingerprint: FingerprintConfig,
    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Timeout configuration
    #[serde(default)]
    pub timeout: TimeoutConfig,
    /// Security configuration
    #[serde(default)]
    pub security: SecurityConfig,
    /// Telemetry configuration
    /// Controls metrics, tracing, and observability features
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// Global header manipulation (optional)
    /// Allows adding or removing headers for all routes
    #[serde(default)]
    pub headers: Option<HeaderManipulation>,
    /// Backend connection pool settings
    /// Controls idle timeout and max idle connections per host
    #[serde(default)]
    pub backend_pool: BackendPoolConfig,
}

/// Config split into its static and dynamic halves.
#[derive(Debug, Clone)]
pub struct ConfigParts {
    /// Process-level settings that require a restart to change.
    pub static_cfg: StaticConfig,
    /// Hot-reloadable settings; wrap in `ArcSwap` for atomic runtime swaps.
    pub dynamic_cfg: DynamicConfig,
}

impl Config {
    /// Validate cross-references within the config.
    pub fn validate_cross_refs(&self) -> crate::error::Result<()> {
        let backend_addrs: HashSet<&str> =
            self.backends.iter().map(|b| b.address.as_str()).collect();

        for route in &self.routes {
            if !backend_addrs.contains(route.backend.as_str()) {
                return Err(crate::error::ProxyError::Config(format!(
                    "Route '{}' references unknown backend '{}' (known: [{}])",
                    route.prefix,
                    route.backend,
                    backend_addrs.iter().copied().collect::<Vec<_>>().join(", ")
                )));
            }
        }
        for backend in &self.backends {
            if let Some(hc) = &backend.health_check {
                hc.validate()?;
            }
        }
        Ok(())
    }

    /// Decompose the deserialized config into its static and dynamic parts.
    ///
    /// - `StaticConfig` holds process-level settings (listen addrs, TLS stack,
    ///   logging, timeouts, `max_connections`). Changing these requires a restart.
    /// - `DynamicConfig` holds hot-reloadable settings (routes, backends, headers,
    ///   security policy). Wrap the returned value in `ArcSwap` to support
    ///   atomic hot-swaps at runtime.
    pub fn into_parts(self) -> ConfigParts {
        ConfigParts {
            static_cfg: StaticConfig {
                listen: self.listen,
                tls: self.tls,
                fingerprint: self.fingerprint,
                logging: self.logging,
                timeout: self.timeout,
                telemetry: self.telemetry,
                max_connections: self.security.max_connections,
            },
            dynamic_cfg: DynamicConfig {
                backends: self.backends,
                routes: {
                    let mut routes = self.routes;
                    super::sort_routes(&mut routes);
                    routes
                },
                preserve_host: self.preserve_host,
                headers: self.headers,
                security: SecurityDynamicConfig {
                    headers: self.security.headers,
                    ip_filter: self.security.ip_filter,
                    rate_limit: self.security.rate_limit,
                },
                backend_pool: self.backend_pool,
            },
        }
    }
}
