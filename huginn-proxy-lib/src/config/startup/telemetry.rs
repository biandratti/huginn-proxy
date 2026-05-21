use std::{str::FromStr, time::Duration};

use serde::Deserialize;

use crate::telemetry::OpentelemetryConfig;

/// Telemetry configuration
/// Controls observability features: metrics, tracing, and OpenTelemetry integration
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
pub struct TelemetryConfig {
    /// Metrics server port (optional)
    /// If provided, starts a separate HTTP server on this port for Prometheus metrics
    /// This is the recommended production approach, similar to how Traefik handles metrics
    /// Default: None (metrics disabled)
    #[serde(default)]
    pub metrics_port: Option<u16>,
    pub otel: Option<OtelConfig>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct OtelConfig {
    pub endpoint: String,
    #[serde(default = "default_otel_tracer_name")]
    pub tracer_name: String,
    #[serde(default = "default_otel_resource_name")]
    pub resource_name: String,
    /// Log level for sending logs to OTEL
    #[serde(default = "default_otel_log_level")]
    pub log_level: LogLevel,
    /// Protocol to use, default = "http_binary"
    pub protocol: OtlpProtocol,
    /// Timeout for sending spans to consumer in seconds
    pub timeout: Option<u64>,
    /// OpenTelemetry internal log level
    /// Controls verbosity of OpenTelemetry SDK internal logs (not application logs)
    /// This is separate from the main application log level in the \[logging\] TOML table
    /// Options: "trace", "debug", "info", "warn", "error"
    /// Default: "warn" (suppress informational logs from OpenTelemetry SDK)
    #[serde(default = "default_otel_sdk_log_level")]
    sdk_log_level: LogLevel,
    #[serde(default)]
    pub show_target: bool,
    #[serde(default = "default_otel_sample_ratio")]
    sample_ratio: f64,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OtlpProtocol {
    #[default]
    HttpBinary,
    HttpJson,
    Grpc,
}

impl From<OtlpProtocol> for opentelemetry_otlp::Protocol {
    fn from(value: OtlpProtocol) -> Self {
        match value {
            OtlpProtocol::HttpBinary => opentelemetry_otlp::Protocol::HttpBinary,
            OtlpProtocol::HttpJson => opentelemetry_otlp::Protocol::HttpJson,
            OtlpProtocol::Grpc => opentelemetry_otlp::Protocol::Grpc,
        }
    }
}

// TODO: whats a good default here?
fn default_otel_sample_ratio() -> f64 {
    0.5
}

impl From<OtelConfig> for OpentelemetryConfig {
    fn from(value: OtelConfig) -> Self {
        OpentelemetryConfig::new(
            value.endpoint,
            value.tracer_name,
            value.resource_name,
            value.log_level.into(),
            value.sdk_log_level.into(),
            value.protocol.into(),
            value.timeout.map(Duration::from_secs),
            value.sample_ratio,
        )
    }
}

fn default_otel_tracer_name() -> String {
    "huginn-tracer".to_string()
}

fn default_otel_resource_name() -> String {
    "huginn-proxy".to_string()
}

fn default_otel_sdk_log_level() -> LogLevel {
    LogLevel::Warn
}

fn default_otel_log_level() -> LogLevel {
    LogLevel::Info
}

/// Logging configuration
/// Controls application-level structured logging (stdout/stderr)
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error"
    /// Default: "info"
    /// Can be overridden at runtime via RUST_LOG environment variable
    #[serde(default = "default_log_level")]
    pub level: LogLevel,
    /// Show module path (target) in log messages
    /// Default: false
    #[serde(default = "default_false")]
    pub show_target: bool,
}

fn default_log_level() -> LogLevel {
    LogLevel::Info
}

fn default_false() -> bool {
    false
}

#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            other => Err(format!(
                "unknown log level: {other:?}, expected one of: trace, debug, info, warn, error"
            )),
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        };
        f.write_str(s)
    }
}

impl From<LogLevel> for tracing::Level {
    fn from(l: LogLevel) -> Self {
        match l {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}

impl From<tracing::Level> for LogLevel {
    fn from(l: tracing::Level) -> Self {
        match l {
            tracing::Level::TRACE => Self::Trace,
            tracing::Level::DEBUG => Self::Debug,
            tracing::Level::INFO => Self::Info,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::ERROR => Self::Error,
        }
    }
}
