use serde::{Deserialize, Serialize};

/// Telemetry configuration
/// Controls observability features: metrics, tracing, and OpenTelemetry integration
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Metrics server port (optional)
    /// If provided, starts a separate HTTP server on this port for Prometheus metrics
    /// This is the recommended production approach, similar to how Traefik handles metrics
    /// Default: None (metrics disabled)
    #[serde(default)]
    pub metrics_port: Option<u16>,
    /// OpenTelemetry internal log level
    /// Controls verbosity of OpenTelemetry SDK internal logs (not application logs)
    /// This is separate from the main application log level in the \[logging\] TOML table
    /// Options: "trace", "debug", "info", "warn", "error"
    /// Default: "warn" (suppress informational logs from OpenTelemetry SDK)
    #[serde(default = "default_otel_log_level")]
    pub otel_log_level: String,
}

fn default_otel_log_level() -> String {
    "warn".to_string()
}

/// Logging configuration
/// Controls application-level structured logging (stdout/stderr)
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error"
    /// Default: "info"
    /// Can be overridden at runtime via RUST_LOG environment variable
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Show module path (target) in log messages
    /// Default: false
    #[serde(default = "default_false")]
    pub show_target: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_false() -> bool {
    false
}

/// Allowlisted effective-config view of [`TelemetryConfig`]. Field names are the JSON keys.
#[derive(Serialize)]
pub(crate) struct TelemetryView<'a> {
    metrics_port: Option<u16>,
    otel_log_level: &'a str,
}

/// Allowlisted effective-config view of [`LoggingConfig`]. Field names are the JSON keys.
#[derive(Serialize)]
pub(crate) struct LoggingView<'a> {
    level: &'a str,
    show_target: bool,
}

impl TelemetryConfig {
    pub(crate) fn effective_view(&self) -> TelemetryView<'_> {
        TelemetryView {
            metrics_port: self.metrics_port,
            otel_log_level: self.otel_log_level.as_str(),
        }
    }
}

impl LoggingConfig {
    pub(crate) fn effective_view(&self) -> LoggingView<'_> {
        LoggingView { level: self.level.as_str(), show_target: self.show_target }
    }
}
