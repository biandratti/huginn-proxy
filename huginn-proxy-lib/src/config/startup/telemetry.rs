use serde::Deserialize;

/// Telemetry configuration
/// Controls observability features: metrics, tracing, and OpenTelemetry integration
#[derive(Debug, Deserialize, Clone, Default)]
pub struct TelemetryConfig {
    /// Metrics server port (optional)
    /// If provided, starts a separate HTTP server on this port for Prometheus metrics
    /// This is the recommended production approach, similar to how Traefik handles metrics
    /// Default: None (metrics disabled)
    #[serde(default)]
    pub metrics_port: Option<u16>,
    /// OpenTelemetry internal log level
    /// Controls verbosity of OpenTelemetry SDK internal logs (not application logs)
    /// This is separate from the main application log level in [logging]
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
#[derive(Debug, Deserialize, Clone, Default)]
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
