pub mod fingerprinting;
pub mod listen;
pub mod reload;
pub mod telemetry;
pub mod timeout;
pub mod tls;

use serde::Serialize;

pub use fingerprinting::FingerprintConfig;
pub use listen::{ListenConfig, ProxyProtocolConfig, ProxyProtocolMode};
pub use reload::ReloadConfig;
pub use telemetry::{LoggingConfig, TelemetryConfig};
pub use timeout::{KeepAliveConfig, TimeoutConfig};
pub use tls::{ClientAuth, SessionResumptionConfig, TlsConfig, TlsOptions, TlsVersion};

use fingerprinting::FingerprintView;
use listen::ListenView;
use reload::ReloadView;
use telemetry::{LoggingView, TelemetryView};
use timeout::TimeoutView;
use tls::{effective_tls_view, TlsView};

/// Static configuration read once at startup, requires restart to change.
///
/// Contains all fields that require OS-level resources (socket binding, TLS
/// stack initialization, logging setup) or are too fundamental to change
/// at runtime.
#[derive(Debug, Clone, PartialEq)]
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
    /// Filesystem-watch / hot-reload configuration
    pub reload: ReloadConfig,
    /// Maximum concurrent connections (from \[security\] in TOML)
    pub max_connections: usize,
}

/// Allowlisted effective-config view of [`StaticConfig`]. Each section mirrors one config type;
/// the corresponding `*View` struct lives next to that type in the submodules above.
#[derive(Serialize)]
pub(crate) struct StaticView<'a> {
    listen: ListenView,
    tls: TlsView<'a>,
    fingerprint: FingerprintView,
    logging: LoggingView<'a>,
    timeout: TimeoutView,
    telemetry: TelemetryView<'a>,
    reload: ReloadView,
    max_connections: usize,
}

impl StaticConfig {
    pub(crate) fn effective_view(&self) -> StaticView<'_> {
        StaticView {
            listen: self.listen.effective_view(),
            tls: effective_tls_view(self.tls.as_ref()),
            fingerprint: self.fingerprint.effective_view(),
            logging: self.logging.effective_view(),
            timeout: self.timeout.effective_view(),
            telemetry: self.telemetry.effective_view(),
            reload: self.reload.effective_view(),
            max_connections: self.max_connections,
        }
    }
}
