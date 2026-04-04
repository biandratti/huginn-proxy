use serde::Deserialize;

use super::backend::{Backend, Route};
use super::fingerprinting::FingerprintConfig;
use super::headers::HeaderManipulation;
use super::listen::ListenConfig;
use super::security::SecurityConfig;
use super::telemetry::{LoggingConfig, TelemetryConfig};
use super::timeout::TimeoutConfig;
use super::tls::TlsConfig;

/// Main configuration structure
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
}
