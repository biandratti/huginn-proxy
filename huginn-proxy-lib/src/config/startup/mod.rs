pub mod fingerprinting;
pub mod listen;
pub mod telemetry;
pub mod timeout;
pub mod tls;

pub use fingerprinting::FingerprintConfig;
pub use listen::ListenConfig;
pub use telemetry::{LoggingConfig, TelemetryConfig};
pub use timeout::{KeepAliveConfig, TimeoutConfig};
pub use tls::{ClientAuth, SessionResumptionConfig, TlsConfig, TlsOptions, TlsVersion};

/// Static configuration — read once at startup, requires restart to change.
///
/// Contains all fields that require OS-level resources (socket binding, TLS
/// stack initialization, logging setup) or are too fundamental to change
/// at runtime.
#[derive(Debug, Clone)]
pub struct StaticConfig {
    /// Listener addresses and socket options
    pub listen: ListenConfig,
    /// TLS termination (None = plain HTTP mode)
    pub tls: Option<TlsConfig>,
    /// Fingerprinting feature flags
    pub fingerprint: FingerprintConfig,
    /// Logging level and format
    pub logging: LoggingConfig,
    /// Connection and request timeouts
    pub timeout: TimeoutConfig,
    /// Telemetry / metrics configuration
    pub telemetry: TelemetryConfig,
    /// Maximum concurrent connections (from [security] in TOML)
    pub max_connections: usize,
}
