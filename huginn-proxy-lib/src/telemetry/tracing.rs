use std::time::Duration;

use opentelemetry::global;
use opentelemetry_otlp::{ExportConfig, Protocol, WithExportConfig};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use tracing::level_filters::LevelFilter;
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

#[derive(Debug, Clone)]
pub struct OpentelemetryConfig {
    pub endpoint: Option<String>,
    pub tracer_name: String,
    pub resource_name: String,
    /// Log level for OTEL
    pub log_level: Level,
    /// Log level of opentelemetry_sdk
    pub sdk_log_level: Level,
    /// Protocol to use
    pub protocol: Protocol,
    /// Send timeout
    pub timeout: Option<Duration>,
    /// Sample ratio
    pub sample_ratio: f64,
    pub show_target: bool,
}

fn build_env_filter(app_level: Level, sdk_level: Level) -> EnvFilter {
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{app_level},opentelemetry={sdk_level}")))
}

impl From<OpentelemetryConfig> for ExportConfig {
    fn from(value: OpentelemetryConfig) -> Self {
        // If set programmatically, the /v1/traces route is not auto-appended
        // like in case with env var or default value
        let endpoint = value.endpoint.map(|mut v| {
            v.push_str("/v1/traces");
            v
        });

        Self { endpoint, protocol: value.protocol, timeout: value.timeout }
    }
}

fn fmt_layer<S>(show_target: bool, log_level: Level) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .with_target(show_target)
        .with_filter(LevelFilter::from_level(log_level))
}

pub fn init_tracing_stdout(log_level: Level, show_target: bool) -> TracingGuard {
    tracing_subscriber::registry()
        .with(build_env_filter(log_level, Level::ERROR))
        .with(fmt_layer(show_target, log_level))
        .init();
    TracingGuard { otel_provider: None }
}

// In future if we will be able to log to files will holds guards to files
/// Logger guard, shutdown method should be called on exit
#[derive(Debug, Default)]
pub struct TracingGuard {
    otel_provider: Option<SdkTracerProvider>,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        if let Some(ref p) = self.otel_provider {
            if let Err(e) = p.force_flush() {
                eprintln!("otel tracer flush error: {e}");
            }
            if let Err(e) = p.shutdown() {
                eprintln!("otel tracer shutdown error: {e}");
            }
        }
    }
}

impl TracingGuard {
    pub fn with_otel(otel_provider: SdkTracerProvider) -> Self {
        Self { otel_provider: Some(otel_provider) }
    }
}

/// Initialize tracing with OpenTelemetry integration
pub fn init_tracing_otel(
    log_level: Level,
    show_target: bool,
    otel_config: OpentelemetryConfig,
) -> Result<TracingGuard, Box<dyn std::error::Error + Send + Sync>> {
    let exporter_builder = opentelemetry_otlp::SpanExporterBuilder::new();
    let provider_builder = SdkTracerProvider::builder().with_resource(
        Resource::builder()
            .with_service_name(otel_config.resource_name.clone())
            .build(),
    );

    let sampler =
        Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(otel_config.sample_ratio)) as _);

    let tracer_provider = match otel_config.protocol {
        Protocol::Grpc => {
            println!("building grpc exporter");
            let exporter = exporter_builder
                .with_tonic()
                .with_export_config(otel_config.clone().into())
                .build()?;
            provider_builder
                .with_batch_exporter(exporter)
                .with_sampler(sampler)
                .build()
        }
        Protocol::HttpBinary | Protocol::HttpJson => {
            println!("building http exporter");
            let exporter = exporter_builder
                .with_http()
                .with_export_config(otel_config.clone().into())
                .build()?;
            provider_builder
                .with_batch_exporter(exporter)
                .with_sampler(sampler)
                .build()
        }
    };

    global::set_tracer_provider(tracer_provider.clone());
    let propagator = TraceContextPropagator::new();
    global::set_text_map_propagator(propagator);
    let tracer = global::tracer(otel_config.tracer_name.clone());

    println!("Tracer provider set {otel_config:?}");

    let otel_layer = tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_target(otel_config.show_target)
        .with_filter(LevelFilter::from_level(otel_config.log_level));

    tracing_subscriber::registry()
        .with(build_env_filter(log_level, otel_config.sdk_log_level))
        .with(fmt_layer(show_target, log_level))
        .with(otel_layer)
        .init();

    Ok(TracingGuard::with_otel(tracer_provider))
}
